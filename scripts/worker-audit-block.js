/* ================= Audit fixes v5: persistent store, OTP, idempotency ================= */
const SHORT_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const AUDIT_PRODUCT_IMAGE_MAX_CHARS = 2_500_000;
const AUDIT_CLIENT_KEY_RE = /^[a-zA-Z0-9._:-]{8,120}$/;
let auditSchemaPromise = null;

async function auditEnsureColumn(database, table, column, definition) {
  const info = await database.prepare(`PRAGMA table_info(${table})`).all();
  const exists = (info.results || []).some(row => String(row.name) === column);
  if (!exists) {
    await database.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
  }
}

async function ensureAuditSchema(env) {
  if (!auditSchemaPromise) {
    auditSchemaPromise = (async () => {
      const database = requireDatabase(env);

      await auditEnsureColumn(database, "users", "wallet_balance", "INTEGER NOT NULL DEFAULT 0");
      await auditEnsureColumn(database, "catalog_products", "base_price", "INTEGER NOT NULL DEFAULT 0");
      await auditEnsureColumn(database, "catalog_products", "category", "TEXT NOT NULL DEFAULT 'accessory'");
      await auditEnsureColumn(database, "catalog_products", "category_fa", "TEXT NOT NULL DEFAULT 'لوازم جانبی'");
      await auditEnsureColumn(database, "catalog_products", "description", "TEXT NOT NULL DEFAULT ''");
      await auditEnsureColumn(database, "catalog_products", "image_data", "TEXT NOT NULL DEFAULT ''");
      await auditEnsureColumn(database, "catalog_products", "rating", "INTEGER NOT NULL DEFAULT 5");
      await auditEnsureColumn(database, "catalog_products", "review_count", "INTEGER NOT NULL DEFAULT 0");
      await auditEnsureColumn(database, "catalog_products", "discount_percent", "INTEGER NOT NULL DEFAULT 0");

      await database.batch([
        database.prepare(`
          CREATE TABLE IF NOT EXISTS verified_token_uses (
            token_id TEXT PRIMARY KEY,
            user_id INTEGER,
            purpose TEXT NOT NULL,
            used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          )
        `),
        database.prepare(`
          CREATE TABLE IF NOT EXISTS order_request_keys (
            request_key TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            order_id INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          )
        `),
        database.prepare(`
          CREATE TABLE IF NOT EXISTS festival_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            payload TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          )
        `),
        database.prepare(`
          CREATE TABLE IF NOT EXISTS store_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            rating INTEGER NOT NULL DEFAULT 5,
            review_text TEXT NOT NULL,
            reply_text TEXT NOT NULL DEFAULT '',
            approved INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            replied_at TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          )
        `),
        database.prepare(`
          CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_key TEXT NOT NULL UNIQUE,
            sender_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            subject TEXT NOT NULL,
            message_text TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          )
        `)
      ]);
    })().catch(error => {
      auditSchemaPromise = null;
      throw error;
    });
  }

  return auditSchemaPromise;
}

function auditTokenId(payload) {
  const tokenId = String(payload?.token_id || "").trim();
  return AUDIT_CLIENT_KEY_RE.test(tokenId) ? tokenId : "";
}

async function consumeVerifiedToken(env, payload) {
  const tokenId = auditTokenId(payload);
  if (!tokenId) return false;
  await ensureAuditSchema(env);
  const result = await requireDatabase(env)
    .prepare(`
      INSERT OR IGNORE INTO verified_token_uses (token_id, user_id, purpose)
      VALUES (?, ?, ?)
    `)
    .bind(tokenId, payload.user_id || null, String(payload.purpose || ""))
    .run();
  return Number(result.meta?.changes || 0) === 1;
}

async function createSessionAudit(env, userId, remember = true) {
  const database = requireDatabase(env);
  await database
    .prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
        AND (revoked_at IS NOT NULL OR datetime(expires_at) <= datetime('now'))
    `)
    .bind(userId)
    .run();

  const token = createRandomToken(32);
  const tokenHash = await hash(token);
  const ttl = remember ? SESSION_TTL_MS : SHORT_SESSION_TTL_MS;
  const expiresAt = new Date(Date.now() + ttl).toISOString();
  await database
    .prepare(`INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)`)
    .bind(userId, tokenHash, expiresAt)
    .run();
  return { token, expiresAt };
}

async function handleVerifyCodeAudit(request, env) {
  await ensureAuditSchema(env);
  const body = await request.json().catch(() => ({}));
  const phone = normalizePhone(body.phone);
  const purpose = normalizePurpose(body.purpose);
  const code = normalizeDigits(body.code).replace(/\D/g, "");
  const payload = await readToken(env.OTP_SECRET, body.verification_token);

  if (
    !phone || !/^\d{6}$/.test(code) || !payload ||
    payload.phone !== phone || payload.purpose !== purpose ||
    payload.expires < Date.now()
  ) {
    return json(env, 401, { ok: false, message: "کد منقضی یا نامعتبر است." });
  }

  const otpLimitKey = `otp:${await hash(String(body.verification_token || ""))}`;
  const otpLimit = await checkFailureLimit(
    env, otpLimitKey, OTP_MAX_FAILURES, OTP_LIMIT_WINDOW_MS
  );
  if (!otpLimit.allowed) {
    return json(env, 429, {
      ok: false,
      message: `تلاش‌های کد تأیید بیش از حد مجاز است. ${otpLimit.retryAfterSeconds} ثانیه دیگر تلاش کنید.`
    });
  }

  const otpHash = await hash(`${code}:${env.OTP_SECRET}`);
  if (otpHash !== payload.otpHash) {
    await recordFailure(env, otpLimitKey, OTP_MAX_FAILURES, OTP_LIMIT_WINDOW_MS, OTP_LOCK_MS);
    return json(env, 422, { ok: false, message: "کد تأیید اشتباه است." });
  }
  await clearSecurityLimit(env, otpLimitKey);

  const existingUser = await findUserByPhone(env, phone);
  if (purpose === "register") {
    if (existingUser && !existingUser.is_active) {
      return json(env, 403, {
        ok: false,
        message: "این حساب توسط مدیریت غیرفعال شده است و با ثبت‌نام دوباره فعال نمی‌شود."
      });
    }
    if (existingUser?.username) {
      return json(env, 409, {
        ok: false,
        message: "این شماره قبلاً ثبت‌نام شده است؛ وارد شوید یا بازیابی رمز را بزنید."
      });
    }
  } else {
    if (!existingUser) {
      return json(env, 404, { ok: false, message: "حسابی با این شماره پیدا نشد." });
    }
    if (!existingUser.is_active) {
      return json(env, 403, { ok: false, message: "این حساب غیرفعال شده است." });
    }
  }

  const tokenId = createRandomToken(18);
  const verifiedToken = await makeToken(env.OTP_SECRET, {
    token_id: tokenId,
    user_id: existingUser?.id || null,
    phone,
    purpose,
    verified: true,
    expires: Date.now() + VERIFIED_TOKEN_TTL_MS
  });

  return json(env, 200, {
    ok: true,
    verified: true,
    message: purpose === "register"
      ? "شماره تأیید شد؛ نام کاربری و رمز را تکمیل کنید."
      : "شماره برای بازیابی رمز تأیید شد.",
    verified_token: verifiedToken,
    user: existingUser ? serializeUser(existingUser) : null
  });
}

async function handleRegisterAudit(request, env) {
  await ensureAuditSchema(env);
  const body = await request.json().catch(() => ({}));
  const phone = normalizePhone(body.phone);
  const username = normalizeUsername(body.username);
  const password = normalizePassword(body.password);
  const passwordConfirm = normalizePassword(body.password_confirm);

  if (!phone) return json(env, 422, { ok: false, message: "شماره موبایل معتبر نیست." });
  if (!username) return json(env, 422, {
    ok: false,
    message: "نام کاربری باید ۴ تا ۲۴ کاراکتر، با حرف انگلیسی شروع شود و فقط شامل حروف انگلیسی، عدد و _ باشد."
  });
  if (username === "admin") return json(env, 422, { ok: false, message: "نام کاربری admin برای مدیریت رزرو شده است." });
  if (!validPassword(password)) return json(env, 422, {
    ok: false,
    message: "رمز باید ۸ تا ۶۴ کاراکتر و شامل حرف بزرگ، حرف کوچک، عدد و علامت باشد و فاصله نداشته باشد."
  });
  if (password !== passwordConfirm) return json(env, 422, { ok: false, message: "تکرار رمز عبور یکسان نیست." });

  const payload = await readToken(env.OTP_SECRET, body.verification_token);
  if (
    !payload || payload.verified !== true || payload.purpose !== "register" ||
    payload.phone !== phone || payload.expires < Date.now() || !auditTokenId(payload)
  ) {
    return json(env, 401, { ok: false, message: "تأیید شماره منقضی یا نامعتبر است." });
  }

  const database = requireDatabase(env);
  const existingPhone = await findUserByPhone(env, phone);
  if (existingPhone && !existingPhone.is_active) {
    return json(env, 403, { ok: false, message: "این حساب توسط مدیریت غیرفعال شده است." });
  }
  if (existingPhone?.username) {
    return json(env, 409, { ok: false, message: "این شماره قبلاً ثبت‌نام شده است." });
  }
  const existingUsername = await database
    .prepare(`SELECT id FROM users WHERE username = ? COLLATE NOCASE LIMIT 1`)
    .bind(username)
    .first();
  if (existingUsername && Number(existingUsername.id) !== Number(existingPhone?.id || 0)) {
    return json(env, 409, { ok: false, message: "این نام کاربری قبلاً ثبت شده است." });
  }

  if (!(await consumeVerifiedToken(env, payload))) {
    return json(env, 409, { ok: false, message: "این تأیید قبلاً استفاده شده است؛ کد جدید بگیرید." });
  }

  if (!existingPhone) {
    await database
      .prepare(`INSERT INTO users (phone, is_active) VALUES (?, 1)`)
      .bind(phone)
      .run();
  }
  const user = await findUserByPhone(env, phone);
  if (!user || !user.is_active) {
    return json(env, 409, { ok: false, message: "ساخت حساب کاربری انجام نشد." });
  }

  const passwordHash = await createPasswordHash(password);
  await database
    .prepare(`
      UPDATE users
      SET username = ?, full_name = ?, password_hash = ?,
          password_updated_at = CURRENT_TIMESTAMP, must_change_password = 0,
          is_active = 1, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND phone = ? AND is_active = 1
    `)
    .bind(username, username, passwordHash, user.id, phone)
    .run();
  await database
    .prepare(`UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL`)
    .bind(user.id)
    .run();

  const savedUser = await findUserByPhone(env, phone);
  const session = await createSessionAudit(env, user.id, true);
  return json(env, 200, {
    ok: true,
    message: "ثبت‌نام با موفقیت انجام شد.",
    session_token: session.token,
    session_expires_at: session.expiresAt,
    user: serializeUser(savedUser)
  });
}

async function handlePasswordLoginAudit(request, env) {
  await ensureAuditSchema(env);
  const body = await request.json().catch(() => ({}));
  const identity = String(body.identity || body.username || "").trim();
  const password = normalizePassword(body.password);
  if (!identity || !password) {
    return json(env, 422, { ok: false, message: "نام کاربری/شماره و رمز را وارد کنید." });
  }

  const loginLimitKey = `login:${await hash(identity.toLowerCase())}`;
  const loginLimit = await checkFailureLimit(env, loginLimitKey, LOGIN_MAX_FAILURES, LOGIN_LIMIT_WINDOW_MS);
  if (!loginLimit.allowed) {
    return json(env, 429, {
      ok: false,
      message: `تلاش‌های ورود بیش از حد مجاز است. ${loginLimit.retryAfterSeconds} ثانیه دیگر تلاش کنید.`
    });
  }

  const user = await findUserByIdentity(env, identity);
  const passwordIsValid = Boolean(user?.password_hash && await verifyPassword(password, user.password_hash));
  if (!passwordIsValid) {
    await recordFailure(env, loginLimitKey, LOGIN_MAX_FAILURES, LOGIN_LIMIT_WINDOW_MS, LOGIN_LOCK_MS);
    return json(env, 401, { ok: false, message: "نام کاربری، شماره موبایل یا رمز عبور اشتباه است." });
  }
  await clearSecurityLimit(env, loginLimitKey);
  if (!user.is_active) return json(env, 403, { ok: false, message: "حساب کاربری شما مسدود شده است." });

  const remember = body.remember !== false;
  const session = await createSessionAudit(env, user.id, remember);
  return json(env, 200, {
    ok: true,
    message: "ورود با موفقیت انجام شد.",
    session_token: session.token,
    session_expires_at: session.expiresAt,
    user: serializeUser(user)
  });
}

async function handleAdminLoginAudit(request, env) {
  const response = await handlePasswordLoginAudit(request, env);
  if (!response.ok) return response;
  const payload = await response.json().catch(() => ({}));
  if (!payload.user?.is_admin) {
    if (payload.session_token) {
      await requireDatabase(env)
        .prepare(`UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ?`)
        .bind(await hash(payload.session_token))
        .run();
    }
    return json(env, 403, { ok: false, message: "این حساب دسترسی مدیریت ندارد." });
  }
  return json(env, 200, { ...payload, message: "ورود مدیر با موفقیت انجام شد." });
}

async function handleResetPasswordAudit(request, env) {
  await ensureAuditSchema(env);
  const body = await request.json().catch(() => ({}));
  const phone = normalizePhone(body.phone);
  const password = normalizePassword(body.password);
  const passwordConfirm = normalizePassword(body.password_confirm);
  if (!phone) return json(env, 422, { ok: false, message: "شماره موبایل معتبر نیست." });
  if (!validPassword(password)) return json(env, 422, {
    ok: false,
    message: "رمز باید ۸ تا ۶۴ کاراکتر و شامل حرف بزرگ، حرف کوچک، عدد و علامت باشد و فاصله نداشته باشد."
  });
  if (password !== passwordConfirm) return json(env, 422, { ok: false, message: "تکرار رمز عبور یکسان نیست." });

  const payload = await readToken(env.OTP_SECRET, body.verification_token);
  if (
    !payload || payload.verified !== true || payload.purpose !== "reset" ||
    payload.phone !== phone || payload.expires < Date.now() || !auditTokenId(payload)
  ) {
    return json(env, 401, { ok: false, message: "تأیید بازیابی منقضی یا نامعتبر است." });
  }
  const user = await findUserByPhone(env, phone);
  if (!user || Number(user.id) !== Number(payload.user_id)) {
    return json(env, 404, { ok: false, message: "حسابی با این شماره پیدا نشد." });
  }
  if (!user.is_active) return json(env, 403, { ok: false, message: "این حساب غیرفعال شده است." });
  if (!(await consumeVerifiedToken(env, payload))) {
    return json(env, 409, { ok: false, message: "این تأیید قبلاً استفاده شده است؛ کد جدید بگیرید." });
  }

  const database = requireDatabase(env);
  const passwordHash = await createPasswordHash(password);
  await database.batch([
    database.prepare(`
      UPDATE users
      SET password_hash = ?, password_updated_at = CURRENT_TIMESTAMP,
          must_change_password = 0, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(passwordHash, user.id),
    database.prepare(`
      UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
      WHERE user_id = ? AND revoked_at IS NULL
    `).bind(user.id)
  ]);
  return json(env, 200, { ok: true, message: "رمز عبور با موفقیت تغییر کرد." });
}

function auditCategory(value) {
  const category = String(value || "").trim().toLowerCase();
  return new Set(["laptop", "component", "gaming", "accessory"]).has(category)
    ? category : "accessory";
}

function auditImage(value) {
  const image = String(value || "").trim();
  if (!image) return "";
  if (image.length > AUDIT_PRODUCT_IMAGE_MAX_CHARS) return null;
  if (/^data:image\/(?:png|jpeg|webp);base64,[a-z0-9+/=\r\n]+$/i.test(image)) return image;
  if (/^(?:\.{0,2}\/)?[a-z0-9_./-]+\.(?:png|jpe?g|webp)(?:\?[^"'<>]*)?$/i.test(image)) return image;
  return null;
}

function serializeCatalogProductAudit(product) {
  return {
    id: Number(product.id),
    name: product.name,
    category: product.category || "accessory",
    categoryFa: product.category_fa || "لوازم جانبی",
    description: product.description || "",
    image: product.image_data || "",
    price: Number(product.base_price || product.price || 0),
    sale_price: Number(product.price || 0),
    oldPrice: Number(product.original_price || 0),
    stock: Number(product.stock || 0),
    rating: Number(product.rating || 5),
    reviews: Number(product.review_count || 0),
    discount: Number(product.discount_percent || 0),
    is_active: Boolean(product.is_active),
    updated_at: product.updated_at
  };
}

async function handlePublicProductsAudit(request, env) {
  await ensureAuditSchema(env);
  const database = requireDatabase(env);
  const result = await database.prepare(`
    SELECT id, name, price, original_price, stock, is_active, updated_at,
           base_price, category, category_fa, description, image_data,
           rating, review_count, discount_percent
    FROM catalog_products
    WHERE is_active = 1
    ORDER BY id ASC
  `).all();
  const festivalRow = await database
    .prepare(`SELECT payload FROM festival_settings WHERE id = 1 LIMIT 1`)
    .first();
  let festival = null;
  try { festival = festivalRow?.payload ? JSON.parse(festivalRow.payload) : null; } catch { festival = null; }
  return json(env, 200, {
    ok: true,
    products: (result.results || []).map(serializeCatalogProductAudit),
    festival
  });
}

async function handleAdminProductsSyncAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await requireAdminAuthentication(request, env);
  if (!authentication) return json(env, 403, { ok: false, message: "دسترسی مدیریت معتبر نیست." });
  const body = await request.json().catch(() => ({}));
  const source = Array.isArray(body.products) ? body.products : [];
  if (source.length > 100) return json(env, 422, { ok: false, message: "فهرست محصولات بیش از حد مجاز است." });

  const products = [];
  const seen = new Set();
  for (const row of source) {
    const id = normalizePositiveInteger(row.id, Number.MAX_SAFE_INTEGER);
    const name = normalizeOrderText(row.name, 120);
    const category = auditCategory(row.category);
    const categoryFa = normalizeOrderText(row.categoryFa || row.category_fa, 40) || "لوازم جانبی";
    const description = normalizeMultilineOrderText(row.description, 800);
    const image = auditImage(row.image);
    const basePrice = normalizeMoney(row.price);
    const oldPrice = normalizeMoney(row.oldPrice ?? row.original_price ?? 0);
    const stock = Number(normalizeDigits(row.stock));
    const rating = Number(row.rating ?? 5);
    const reviewCount = Number(row.reviews ?? row.review_count ?? 0);
    const discount = Math.trunc(Number(row.discount || 0));
    if (
      !id || seen.has(id) || name.length < 2 || image === null || basePrice < 0 || oldPrice < 0 ||
      !Number.isInteger(stock) || stock < 0 || stock > 1_000_000 ||
      !Number.isInteger(rating) || rating < 1 || rating > 5 ||
      !Number.isInteger(reviewCount) || reviewCount < 0 || reviewCount > 1_000_000 ||
      !Number.isInteger(discount) || discount < 0 || discount > 90
    ) {
      return json(env, 422, { ok: false, message: "اطلاعات یکی از محصولات معتبر نیست." });
    }
    const salePrice = discount > 0
      ? Math.max(0, Math.round((basePrice * (1 - discount / 100)) / 1000) * 1000)
      : basePrice;
    seen.add(id);
    products.push({ id, name, category, categoryFa, description, image, basePrice,
      salePrice, oldPrice: Math.max(oldPrice, basePrice), stock, rating, reviewCount, discount });
  }

  const database = requireDatabase(env);
  const statements = [
    database.prepare(`UPDATE catalog_products SET is_active = 0, updated_at = CURRENT_TIMESTAMP`),
    database.prepare(`UPDATE products SET is_active = 0, updated_at = CURRENT_TIMESTAMP`)
  ];
  for (const product of products) {
    statements.push(database.prepare(`
      INSERT INTO catalog_products (
        id, name, price, original_price, stock, is_active, updated_at,
        base_price, category, category_fa, description, image_data,
        rating, review_count, discount_percent
      ) VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name, price = excluded.price, original_price = excluded.original_price,
        stock = excluded.stock, is_active = 1, base_price = excluded.base_price,
        category = excluded.category, category_fa = excluded.category_fa,
        description = excluded.description, image_data = excluded.image_data,
        rating = excluded.rating, review_count = excluded.review_count,
        discount_percent = excluded.discount_percent, updated_at = CURRENT_TIMESTAMP
    `).bind(
      product.id, product.name, product.salePrice, product.oldPrice, product.stock,
      product.basePrice, product.category, product.categoryFa, product.description,
      product.image, product.rating, product.reviewCount, product.discount
    ));
    statements.push(database.prepare(`
      INSERT INTO products (
        id, title, slug, description, price, compare_at_price, stock,
        image_url, is_active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      ON CONFLICT(id) DO UPDATE SET
        title = excluded.title, description = excluded.description, price = excluded.price,
        compare_at_price = excluded.compare_at_price, stock = excluded.stock,
        image_url = excluded.image_url, is_active = 1, updated_at = CURRENT_TIMESTAMP
    `).bind(
      product.id, product.name, `catalog-${product.id}`, product.description,
      product.salePrice, product.oldPrice, product.stock,
      product.image.startsWith("data:") ? null : (product.image || null)
    ));
  }
  const festivalPayload = JSON.stringify(body.festival && typeof body.festival === "object" ? body.festival : {});
  statements.push(database.prepare(`
    INSERT INTO festival_settings (id, payload, updated_at)
    VALUES (1, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = CURRENT_TIMESTAMP
  `).bind(festivalPayload));
  await database.batch(statements);
  return json(env, 200, {
    ok: true,
    message: "محصولات و جشنواره در دیتابیس همگام شدند.",
    synced_products: products.length
  });
}

function auditRequestKey(value) {
  const key = String(value || "").trim();
  return /^[a-zA-Z0-9._:-]{16,100}$/.test(key) ? key : "";
}

function auditRequestedValues(items) {
  return items.map(() => "(?, ?)").join(", ");
}

function auditRequestedBindings(items) {
  return items.flatMap(item => [Number(item.product_id), Number(item.quantity)]);
}

async function reserveCatalogAudit(env, items) {
  const database = requireDatabase(env);
  const values = auditRequestedValues(items);
  const result = await database.prepare(`
    WITH requested(product_id, quantity) AS (VALUES ${values})
    UPDATE catalog_products
    SET stock = stock - (
          SELECT quantity FROM requested WHERE requested.product_id = catalog_products.id
        ),
        updated_at = CURRENT_TIMESTAMP
    WHERE id IN (SELECT product_id FROM requested)
      AND NOT EXISTS (
        SELECT 1
        FROM requested
        LEFT JOIN catalog_products p ON p.id = requested.product_id
        WHERE p.id IS NULL OR p.is_active <> 1 OR p.stock < requested.quantity
      )
  `).bind(...auditRequestedBindings(items)).run();
  return Number(result.meta?.changes || 0) === items.length;
}

async function restoreCatalogAudit(env, items) {
  if (!items.length) return;
  const database = requireDatabase(env);
  const values = auditRequestedValues(items);
  await database.prepare(`
    WITH requested(product_id, quantity) AS (VALUES ${values})
    UPDATE catalog_products
    SET stock = stock + (
          SELECT quantity FROM requested WHERE requested.product_id = catalog_products.id
        ),
        updated_at = CURRENT_TIMESTAMP
    WHERE id IN (SELECT product_id FROM requested)
  `).bind(...auditRequestedBindings(items)).run();
}

async function handleCreateOrderAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await authenticateRequest(request, env, true);
  if (!authentication) return json(env, 401, { ok: false, message: "نشست ورود نامعتبر یا منقضی شده است." });
  if (authentication.user.must_change_password) {
    return json(env, 403, { ok: false, message: "ابتدا رمز موقت حساب را تغییر دهید." });
  }

  const body = await request.json().catch(() => ({}));
  const requestKey = auditRequestKey(body.request_id);
  if (!requestKey) return json(env, 422, { ok: false, message: "شناسه یکتای سفارش معتبر نیست." });
  const customerName = normalizeOrderText(body.customer_name, 70);
  const delivery = String(body.delivery || "").trim() === "pickup" ? "pickup" : "shipping";
  const province = delivery === "pickup" ? "تحویل حضوری" : normalizeOrderText(body.province, 40);
  const city = delivery === "pickup" ? "فروشگاه" : normalizeOrderText(body.city, 40);
  const postalCode = delivery === "pickup"
    ? "00000"
    : normalizeDigits(body.postal_code).replace(/\D/g, "").slice(0, 20);
  const address = delivery === "pickup"
    ? "تحویل حضوری از فروشگاه"
    : normalizeMultilineOrderText(body.address, 500);
  const note = normalizeMultilineOrderText(body.note, 500);
  const requestedItems = Array.isArray(body.items) ? body.items : [];
  if (
    customerName.length < 2 ||
    (delivery === "shipping" && (province.length < 2 || city.length < 2 || postalCode.length < 5 || address.length < 5)) ||
    requestedItems.length < 1 || requestedItems.length > 50
  ) {
    return json(env, 422, { ok: false, message: "اطلاعات سفارش کامل یا معتبر نیست." });
  }

  const database = requireDatabase(env);
  const priorKey = await database
    .prepare(`SELECT order_id FROM order_request_keys WHERE request_key = ? AND user_id = ? LIMIT 1`)
    .bind(requestKey, authentication.user.id)
    .first();
  if (priorKey?.order_id) {
    const previousOrder = await getOrderById(env, priorKey.order_id);
    if (previousOrder) {
      return json(env, 200, {
        ok: true, duplicate: true,
        message: "این سفارش قبلاً ثبت شده است.",
        tracking_code: previousOrder.code,
        order: previousOrder
      });
    }
    await database.prepare(`DELETE FROM order_request_keys WHERE request_key = ?`).bind(requestKey).run();
  }

  const keyInsert = await database.prepare(`
    INSERT OR IGNORE INTO order_request_keys (request_key, user_id)
    VALUES (?, ?)
  `).bind(requestKey, authentication.user.id).run();
  if (Number(keyInsert.meta?.changes || 0) !== 1) {
    return json(env, 409, { ok: false, message: "درخواست سفارش مشابه در حال پردازش است." });
  }

  const itemQuantities = new Map();
  for (const row of requestedItems) {
    const productId = normalizePositiveInteger(row.product_id, Number.MAX_SAFE_INTEGER);
    const quantity = normalizePositiveInteger(row.quantity, 1000);
    if (!productId || !quantity) {
      await database.prepare(`DELETE FROM order_request_keys WHERE request_key = ?`).bind(requestKey).run();
      return json(env, 422, { ok: false, message: "تعداد یا شناسه یکی از محصولات معتبر نیست." });
    }
    itemQuantities.set(productId, (itemQuantities.get(productId) || 0) + quantity);
  }

  const productIds = [...itemQuantities.keys()];
  const placeholders = productIds.map(() => "?").join(",");
  const productResult = await database.prepare(`
    SELECT id, name, price, original_price, stock, is_active
    FROM catalog_products WHERE id IN (${placeholders})
  `).bind(...productIds).all();
  const productMap = new Map((productResult.results || []).map(product => [Number(product.id), product]));
  const trustedItems = [];
  for (const productId of productIds) {
    const product = productMap.get(productId);
    const quantity = itemQuantities.get(productId);
    if (!product || !product.is_active || Number(product.stock) < quantity) {
      await database.prepare(`DELETE FROM order_request_keys WHERE request_key = ?`).bind(requestKey).run();
      return json(env, 409, { ok: false, message: "موجودی یا قیمت یکی از محصولات تغییر کرده است." });
    }
    trustedItems.push({
      product_id: productId,
      product_title: product.name,
      quantity,
      unit_price: Number(product.price),
      line_total: Number(product.price) * quantity
    });
  }
  const total = trustedItems.reduce((sum, item) => sum + item.line_total, 0);
  if (!Number.isSafeInteger(total) || total < 0) {
    await database.prepare(`DELETE FROM order_request_keys WHERE request_key = ?`).bind(requestKey).run();
    return json(env, 422, { ok: false, message: "مبلغ سفارش معتبر نیست." });
  }

  if (!(await reserveCatalogAudit(env, trustedItems))) {
    await database.prepare(`DELETE FROM order_request_keys WHERE request_key = ?`).bind(requestKey).run();
    return json(env, 409, { ok: false, message: "موجودی یکی از محصولات به‌تازگی تمام شده است." });
  }

  const orderNumber = createOrderNumber();
  try {
    const statements = [database.prepare(`
      INSERT INTO orders (
        order_number, user_id, customer_phone, receiver_name, receiver_phone,
        shipping_address, postal_code, total_amount, status, payment_status,
        province, city, delivery, note, inventory_restored, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'unpaid', ?, ?, ?, ?, 0,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).bind(
      orderNumber, authentication.user.id, authentication.user.phone,
      customerName, authentication.user.phone, address, postalCode, total,
      province, city, delivery, note
    )];
    for (const item of trustedItems) {
      statements.push(database.prepare(`
        INSERT INTO order_items (
          order_id, product_id, product_title, unit_price, quantity, line_total, created_at
        ) VALUES ((SELECT id FROM orders WHERE order_number = ? LIMIT 1), ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).bind(orderNumber, item.product_id, item.product_title, item.unit_price, item.quantity, item.line_total));
    }
    await database.batch(statements);
  } catch (error) {
    await restoreCatalogAudit(env, trustedItems);
    await database.prepare(`DELETE FROM order_request_keys WHERE request_key = ?`).bind(requestKey).run();
    throw error;
  }

  const saved = await database.prepare(`SELECT id FROM orders WHERE order_number = ? LIMIT 1`).bind(orderNumber).first();
  if (!saved) {
    await restoreCatalogAudit(env, trustedItems);
    await database.prepare(`DELETE FROM order_request_keys WHERE request_key = ?`).bind(requestKey).run();
    return json(env, 500, { ok: false, message: "ثبت سفارش کامل نشد؛ دوباره تلاش کنید." });
  }
  await database.prepare(`
    UPDATE order_request_keys SET order_id = ?, updated_at = CURRENT_TIMESTAMP WHERE request_key = ?
  `).bind(saved.id, requestKey).run();
  const order = await getOrderById(env, saved.id);
  return json(env, 201, {
    ok: true,
    message: "سفارش با موفقیت در دیتابیس ثبت شد.",
    tracking_code: order.code,
    order
  });
}

async function handleAdminOrderStatusAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await requireAdminAuthentication(request, env);
  if (!authentication) return json(env, 403, { ok: false, message: "دسترسی مدیریت معتبر نیست." });
  const body = await request.json().catch(() => ({}));
  const orderId = normalizePositiveInteger(body.id, Number.MAX_SAFE_INTEGER);
  const nextStatus = normalizeOrderStatus(body.status);
  if (!orderId || !nextStatus) return json(env, 422, { ok: false, message: "شناسه یا وضعیت سفارش معتبر نیست." });

  const database = requireDatabase(env);
  const order = await database.prepare(`SELECT * FROM orders WHERE id = ? LIMIT 1`).bind(orderId).first();
  if (!order) return json(env, 404, { ok: false, message: "سفارش پیدا نشد." });
  const grouped = await getOrderItems(env, [orderId]);
  const items = grouped.get(orderId) || [];
  const previousStatus = normalizeOrderStatus(order.status, "new");
  const restored = Boolean(order.inventory_restored);

  if (nextStatus === "cancelled" && previousStatus !== "cancelled" && !restored) {
    const statements = items.map(item => database.prepare(`
      UPDATE catalog_products SET stock = stock + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `).bind(Number(item.quantity), Number(item.product_id)));
    statements.push(database.prepare(`
      UPDATE orders SET status = 'cancelled', inventory_restored = 1, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND inventory_restored = 0
    `).bind(orderId));
    await database.batch(statements);
  } else if (previousStatus === "cancelled" && nextStatus !== "cancelled") {
    if (!(await reserveCatalogAudit(env, items))) {
      return json(env, 409, { ok: false, message: "موجودی کافی برای فعال‌کردن دوباره این سفارش وجود ندارد." });
    }
    try {
      await database.prepare(`
        UPDATE orders SET status = ?, inventory_restored = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?
      `).bind(orderStatusForDatabase(nextStatus), orderId).run();
    } catch (error) {
      await restoreCatalogAudit(env, items);
      throw error;
    }
  } else {
    await database.prepare(`UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .bind(orderStatusForDatabase(nextStatus), orderId)
      .run();
  }
  return json(env, 200, {
    ok: true,
    message: "وضعیت سفارش تغییر کرد.",
    order: await getOrderById(env, orderId)
  });
}

async function handleAdminOrderDeleteAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await requireAdminAuthentication(request, env);
  if (!authentication) return json(env, 403, { ok: false, message: "دسترسی مدیریت معتبر نیست." });
  const body = await request.json().catch(() => ({}));
  const orderId = normalizePositiveInteger(body.id, Number.MAX_SAFE_INTEGER);
  if (!orderId) return json(env, 422, { ok: false, message: "شناسه سفارش معتبر نیست." });

  const database = requireDatabase(env);
  const order = await database.prepare(`SELECT * FROM orders WHERE id = ? LIMIT 1`).bind(orderId).first();
  if (!order) return json(env, 404, { ok: false, message: "سفارش پیدا نشد." });
  const grouped = await getOrderItems(env, [orderId]);
  const items = grouped.get(orderId) || [];
  const statements = [];
  if (!Boolean(order.inventory_restored)) {
    for (const item of items) {
      statements.push(database.prepare(`
        UPDATE catalog_products SET stock = stock + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
      `).bind(Number(item.quantity), Number(item.product_id)));
    }
  }
  statements.push(database.prepare(`DELETE FROM order_items WHERE order_id = ?`).bind(orderId));
  statements.push(database.prepare(`DELETE FROM order_request_keys WHERE order_id = ?`).bind(orderId));
  statements.push(database.prepare(`DELETE FROM orders WHERE id = ?`).bind(orderId));
  await database.batch(statements);
  return json(env, 200, { ok: true, message: "سفارش حذف شد و موجودی آن بازگردانده شد." });
}

function auditClientKey(prefix, row) {
  const supplied = String(row?.client_key || "").trim();
  if (AUDIT_CLIENT_KEY_RE.test(supplied)) return supplied;
  const numericId = Number(row?.id);
  if (Number.isSafeInteger(numericId) && numericId > 0) return `${prefix}:${numericId}`;
  return "";
}

function auditReviewRow(row) {
  const clientKey = auditClientKey("review", row);
  const name = normalizeOrderText(row?.name, 70);
  const text = normalizeMultilineOrderText(row?.text, 1000);
  const rating = Math.trunc(Number(row?.rating));
  if (!clientKey || name.length < 2 || text.length < 3 || rating < 1 || rating > 5) return null;
  return {
    clientKey, name, text, rating,
    reply: normalizeMultilineOrderText(row?.reply, 1000),
    approved: Boolean(row?.approved),
    createdAt: Number(row?.createdAt) || Date.now(),
    repliedAt: row?.repliedAt ? Number(row.repliedAt) : null
  };
}

function serializeReviewAudit(row) {
  const idPart = String(row.client_key || "").split(":").pop();
  const clientId = Number(idPart);
  return {
    id: Number.isSafeInteger(clientId) && clientId > 0 ? clientId : Number(row.id),
    client_key: row.client_key,
    name: row.name,
    rating: Number(row.rating),
    text: row.review_text,
    reply: row.reply_text || "",
    approved: Boolean(row.approved),
    createdAt: Date.parse(row.created_at) || Date.now(),
    repliedAt: row.replied_at ? Date.parse(row.replied_at) : null
  };
}

async function handleReviewsGetAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await authenticateRequest(request, env, false);
  const isAdmin = Boolean(authentication?.user?.is_admin);
  const result = await requireDatabase(env).prepare(`
    SELECT * FROM store_reviews
    ${isAdmin ? "" : "WHERE approved = 1"}
    ORDER BY datetime(created_at) DESC, id DESC
    LIMIT 200
  `).all();
  return json(env, 200, { ok: true, reviews: (result.results || []).map(serializeReviewAudit) });
}

async function handleReviewsSyncAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await authenticateRequest(request, env, false);
  const isAdmin = Boolean(authentication?.user?.is_admin);
  const body = await request.json().catch(() => ({}));
  const source = Array.isArray(body.reviews) ? body.reviews.slice(0, 200) : [];
  const rows = source.map(auditReviewRow).filter(Boolean);
  const database = requireDatabase(env);
  const statements = [];
  for (const row of rows) {
    if (isAdmin) {
      statements.push(database.prepare(`
        INSERT INTO store_reviews (
          client_key, name, rating, review_text, reply_text, approved, created_at, replied_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(client_key) DO UPDATE SET
          name = excluded.name, rating = excluded.rating, review_text = excluded.review_text,
          reply_text = excluded.reply_text, approved = excluded.approved,
          replied_at = excluded.replied_at, updated_at = CURRENT_TIMESTAMP
      `).bind(
        row.clientKey, row.name, row.rating, row.text, row.reply, row.approved ? 1 : 0,
        new Date(row.createdAt).toISOString(), row.repliedAt ? new Date(row.repliedAt).toISOString() : null
      ));
    } else {
      statements.push(database.prepare(`
        INSERT OR IGNORE INTO store_reviews (
          client_key, name, rating, review_text, reply_text, approved, created_at, updated_at
        ) VALUES (?, ?, ?, ?, '', 0, ?, CURRENT_TIMESTAMP)
      `).bind(row.clientKey, row.name, row.rating, row.text, new Date(row.createdAt).toISOString()));
    }
  }
  if (isAdmin) {
    if (rows.length) {
      const placeholders = rows.map(() => "?").join(",");
      statements.push(database.prepare(`DELETE FROM store_reviews WHERE client_key NOT IN (${placeholders})`)
        .bind(...rows.map(row => row.clientKey)));
    } else {
      statements.push(database.prepare(`DELETE FROM store_reviews`));
    }
  }
  if (statements.length) await database.batch(statements);
  return handleReviewsGetAudit(request, env);
}

function auditMessageRow(row) {
  const clientKey = auditClientKey("message", row);
  const name = normalizeOrderText(row?.name, 70);
  const phone = normalizePhone(row?.phone);
  const subject = normalizeOrderText(row?.subject, 80);
  const text = normalizeMultilineOrderText(row?.text, 1500);
  if (!clientKey || name.length < 2 || !phone || subject.length < 2 || text.length < 3) return null;
  return {
    clientKey, name, phone, subject, text,
    read: Boolean(row?.read),
    createdAt: Number(row?.createdAt) || Date.now()
  };
}

function serializeMessageAudit(row) {
  const idPart = String(row.client_key || "").split(":").pop();
  const clientId = Number(idPart);
  return {
    id: Number.isSafeInteger(clientId) && clientId > 0 ? clientId : Number(row.id),
    client_key: row.client_key,
    name: row.sender_name,
    phone: row.phone,
    subject: row.subject,
    text: row.message_text,
    read: Boolean(row.is_read),
    createdAt: Date.parse(row.created_at) || Date.now()
  };
}

async function handleMessagesGetAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await requireAdminAuthentication(request, env);
  if (!authentication) return json(env, 403, { ok: false, message: "دسترسی مدیریت معتبر نیست." });
  const result = await requireDatabase(env).prepare(`
    SELECT * FROM contact_messages
    ORDER BY datetime(created_at) DESC, id DESC
    LIMIT 300
  `).all();
  return json(env, 200, { ok: true, messages: (result.results || []).map(serializeMessageAudit) });
}

async function handleMessagesSyncAudit(request, env) {
  await ensureAuditSchema(env);
  const authentication = await authenticateRequest(request, env, false);
  const isAdmin = Boolean(authentication?.user?.is_admin);
  const body = await request.json().catch(() => ({}));
  const source = Array.isArray(body.messages) ? body.messages.slice(0, 300) : [];
  const rows = source.map(auditMessageRow).filter(Boolean);
  const database = requireDatabase(env);
  const statements = [];
  for (const row of rows) {
    if (isAdmin) {
      statements.push(database.prepare(`
        INSERT INTO contact_messages (
          client_key, sender_name, phone, subject, message_text, is_read, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(client_key) DO UPDATE SET
          sender_name = excluded.sender_name, phone = excluded.phone, subject = excluded.subject,
          message_text = excluded.message_text, is_read = excluded.is_read,
          updated_at = CURRENT_TIMESTAMP
      `).bind(
        row.clientKey, row.name, row.phone, row.subject, row.text,
        row.read ? 1 : 0, new Date(row.createdAt).toISOString()
      ));
    } else {
      statements.push(database.prepare(`
        INSERT OR IGNORE INTO contact_messages (
          client_key, sender_name, phone, subject, message_text, is_read, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP)
      `).bind(row.clientKey, row.name, row.phone, row.subject, row.text, new Date(row.createdAt).toISOString()));
    }
  }
  if (isAdmin) {
    if (rows.length) {
      const placeholders = rows.map(() => "?").join(",");
      statements.push(database.prepare(`DELETE FROM contact_messages WHERE client_key NOT IN (${placeholders})`)
        .bind(...rows.map(row => row.clientKey)));
    } else {
      statements.push(database.prepare(`DELETE FROM contact_messages`));
    }
  }
  if (statements.length) await database.batch(statements);
  if (isAdmin) return handleMessagesGetAudit(request, env);
  return json(env, 200, { ok: true, message: "پیام برای مدیریت ثبت شد." });
}

async function forwardStoreAudit(request, env, pathname) {
  if (!env.PRESENCE) return json(env, 503, { ok: false, message: "هماهنگ‌کننده سفارش در دسترس نیست." });
  const body = await request.text();
  const headers = new Headers({ "Content-Type": "application/json" });
  const authorization = request.headers.get("Authorization");
  if (authorization) headers.set("Authorization", authorization);
  const stub = env.PRESENCE.getByName("store-coordinator-v2");
  return stub.fetch(`https://store.local${pathname}`, { method: "POST", headers, body });
}
/* ================= End audit fixes v5 ================= */

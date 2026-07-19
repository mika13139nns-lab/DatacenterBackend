import { DurableObject } from "cloudflare:workers";

const SMS_API =
  "https://api.sms-gate.app/3rdparty/v1/messages?skipPhoneValidation=true&deviceActiveWithin=12";

const PRESENCE_TTL_MS = 45_000;
const PRESENCE_STORAGE_KEY = "online-visitors";

const OTP_TTL_MS = 5 * 60 * 1000;
const VERIFIED_TOKEN_TTL_MS = 15 * 60 * 1000;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const PASSWORD_ITERATIONS = 100_000;
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_KEY_BYTES = 32;
const PROFILE_AVATAR_MAX_CHARS = 700_000;
const USERNAME_CHANGE_INTERVAL_MS = 30 * 24 * 60 * 60 * 1000;
const LOGIN_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 5;
const OTP_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const OTP_LOCK_MS = 15 * 60 * 1000;
const OTP_MAX_FAILURES = 5;
const SMS_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const SMS_MIN_INTERVAL_MS = 60 * 1000;
const SMS_MAX_PER_WINDOW = 5;

let profileSchemaPromise = null;
let securitySchemaPromise = null;

function headers(env) {
  const allowedOrigin = String(env.ALLOWED_ORIGIN || "").trim();

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-CSRF-Token",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };
}

function json(env, status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers: headers(env)
  });
}

function normalizeDigits(value) {
  return String(value || "")
    .replace(/[۰-۹]/g, character =>
      String("۰۱۲۳۴۵۶۷۸۹".indexOf(character))
    )
    .replace(/[٠-٩]/g, character =>
      String("٠١٢٣٤٥٦٧٨٩".indexOf(character))
    );
}

function normalizePhone(value) {
  const phone = normalizeDigits(value).replace(/\D/g, "");
  return /^09\d{9}$/.test(phone) ? phone : "";
}

function normalizeUsername(value) {
  const username = String(value || "").trim().toLowerCase();
  return /^[a-z][a-z0-9_]{3,23}$/.test(username) ? username : "";
}

function normalizeAvatarData(value) {
  const avatar = String(value ?? "").trim();

  if (!avatar) {
    return "";
  }

  if (avatar.length > PROFILE_AVATAR_MAX_CHARS) {
    return null;
  }

  return /^data:image\/(?:png|jpeg|webp);base64,[a-z0-9+/=]+$/i.test(avatar)
    ? avatar
    : null;
}

function normalizePurpose(value) {
  return String(value || "").trim().toLowerCase() === "reset"
    ? "reset"
    : "register";
}

function normalizePassword(value) {
  return String(value || "").normalize("NFKC");
}

function validPassword(password) {
  const value = normalizePassword(password);

  return (
    value.length >= 8 &&
    value.length <= 64 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value) &&
    !/\s/.test(value)
  );
}

function createOtp() {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return String(100000 + (values[0] % 900000));
}

function encode(bytes) {
  let text = "";

  for (const byte of bytes) {
    text += String.fromCharCode(byte);
  }

  return btoa(text)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decode(text) {
  const value = String(text || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);

  return Uint8Array.from(
    atob(padded),
    character => character.charCodeAt(0)
  );
}

function createRandomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return encode(bytes);
}

async function sign(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(text)
  );

  return new Uint8Array(signature);
}

async function makeToken(secret, payload) {
  const body = encode(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const signature = encode(await sign(secret, body));
  return `${body}.${signature}`;
}

async function readToken(secret, token) {
  try {
    if (!String(secret || "").trim()) {
      return null;
    }

    const parts = String(token || "").split(".");

    if (parts.length !== 2) {
      return null;
    }

    const expected = await sign(secret, parts[0]);
    const received = decode(parts[1]);

    if (expected.length !== received.length) {
      return null;
    }

    let different = 0;

    for (let index = 0; index < expected.length; index++) {
      different |= expected[index] ^ received[index];
    }

    if (different !== 0) {
      return null;
    }

    return JSON.parse(
      new TextDecoder().decode(decode(parts[0]))
    );
  } catch {
    return null;
  }
}

async function hash(text) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );

  return encode(new Uint8Array(result));
}

function constantTimeEqualBytes(first, second) {
  if (first.length !== second.length) {
    return false;
  }

  let different = 0;

  for (let index = 0; index < first.length; index++) {
    different |= first[index] ^ second[index];
  }

  return different === 0;
}

async function derivePasswordBytes(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(normalizePassword(password)),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    key,
    PASSWORD_KEY_BYTES * 8
  );

  return new Uint8Array(bits);
}

async function createPasswordHash(password) {
  const salt = new Uint8Array(PASSWORD_SALT_BYTES);
  crypto.getRandomValues(salt);

  const derived = await derivePasswordBytes(
    password,
    salt,
    PASSWORD_ITERATIONS
  );

  return [
    "pbkdf2-sha256",
    String(PASSWORD_ITERATIONS),
    encode(salt),
    encode(derived)
  ].join("$");
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = String(storedHash || "").split("$");

    if (
      parts.length !== 4 ||
      parts[0] !== "pbkdf2-sha256"
    ) {
      return false;
    }

    const iterations = Number(parts[1]);

    if (
      !Number.isInteger(iterations) ||
      iterations < 10_000 ||
      iterations > 1_000_000
    ) {
      return false;
    }

    const salt = decode(parts[2]);
    const expected = decode(parts[3]);
    const received = await derivePasswordBytes(
      password,
      salt,
      iterations
    );

    return constantTimeEqualBytes(expected, received);
  } catch {
    return false;
  }
}

async function sendSms(env, phone, otp, purpose) {
  const username = String(env.SMS_USERNAME || "").trim();
  const password = String(env.SMS_PASSWORD || "").trim();
  const deviceId = String(env.SMS_DEVICE_ID || "").trim();
  const simNumber = Number(String(env.SIM_NUMBER || "1").trim());

  if (!username || !password || !deviceId) {
    throw new Error("تنظیمات SMS Gateway کامل نیست.");
  }

  if (simNumber !== 1 && simNumber !== 2) {
    throw new Error("شماره سیم‌کارت باید 1 یا 2 باشد.");
  }

  const title =
    purpose === "reset"
      ? "کد ورود و بازیابی حساب در فروشگاه دیتاسنتر:"
      : "کد تأیید ثبت‌نام در فروشگاه دیتاسنتر:";

  const smsText =
    `${title}\n${otp}\nاین کد را در اختیار دیگران قرار ندهید.`;

  const response = await fetch(SMS_API, {
    method: "POST",
    headers: {
      "Authorization": `Basic ${btoa(`${username}:${password}`)}`,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      textMessage: {
        text: smsText
      },
      deviceId,
      phoneNumbers: [`+98${phone.slice(1)}`],
      simNumber,
      ttl: 300,
      priority: 100
    })
  });

  const raw = await response.text();
  let data = {};

  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { message: raw };
  }

  console.log("SMS Gate response:", response.status, data);

  if (!response.ok) {
    throw new Error(
      `SMS Gate ${response.status}: ${data.message || "خطای نامشخص"}`
    );
  }

  return data;
}

function requireDatabase(env) {
  if (!env.datacenter_db) {
    throw new Error(
      "اتصال دیتابیس با binding نام datacenter_db تنظیم نشده است."
    );
  }

  return env.datacenter_db;
}

async function ensureProfileSchema(env) {
  if (!profileSchemaPromise) {
    profileSchemaPromise = (async () => {
      const database = requireDatabase(env);

      await database
        .prepare(`
          CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY,
            avatar_data TEXT NOT NULL DEFAULT '',
            last_username_change_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          )
        `)
        .run();
    })().catch(error => {
      profileSchemaPromise = null;
      throw error;
    });
  }

  return profileSchemaPromise;
}

async function ensureSecuritySchema(env) {
  if (!securitySchemaPromise) {
    securitySchemaPromise = (async () => {
      const database = requireDatabase(env);

      await database
        .prepare(`
          CREATE TABLE IF NOT EXISTS security_limits (
            limit_key TEXT PRIMARY KEY,
            action_count INTEGER NOT NULL DEFAULT 0,
            window_started_at INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0,
            last_action_at INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          )
        `)
        .run();
    })().catch(error => {
      securitySchemaPromise = null;
      throw error;
    });
  }

  return securitySchemaPromise;
}

async function readSecurityLimit(env, limitKey) {
  await ensureSecuritySchema(env);
  const database = requireDatabase(env);

  return database
    .prepare(`
      SELECT
        action_count,
        window_started_at,
        locked_until,
        last_action_at
      FROM security_limits
      WHERE limit_key = ?
      LIMIT 1
    `)
    .bind(limitKey)
    .first();
}

async function saveSecurityLimit(env, limitKey, values) {
  await ensureSecuritySchema(env);
  const database = requireDatabase(env);

  await database
    .prepare(`
      INSERT INTO security_limits (
        limit_key,
        action_count,
        window_started_at,
        locked_until,
        last_action_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(limit_key) DO UPDATE SET
        action_count = excluded.action_count,
        window_started_at = excluded.window_started_at,
        locked_until = excluded.locked_until,
        last_action_at = excluded.last_action_at,
        updated_at = CURRENT_TIMESTAMP
    `)
    .bind(
      limitKey,
      Number(values.actionCount || 0),
      Number(values.windowStartedAt || 0),
      Number(values.lockedUntil || 0),
      Number(values.lastActionAt || 0)
    )
    .run();
}

async function clearSecurityLimit(env, limitKey) {
  await ensureSecuritySchema(env);
  const database = requireDatabase(env);

  await database
    .prepare(`DELETE FROM security_limits WHERE limit_key = ?`)
    .bind(limitKey)
    .run();
}

async function checkFailureLimit(
  env,
  limitKey,
  maximumFailures,
  windowMs
) {
  const now = Date.now();
  const row = await readSecurityLimit(env, limitKey);

  if (!row) {
    return { allowed: true, retryAfterSeconds: 0 };
  }

  const lockedUntil = Number(row.locked_until || 0);

  if (lockedUntil > now) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((lockedUntil - now) / 1000)
      )
    };
  }

  const windowStartedAt = Number(row.window_started_at || 0);

  if (!windowStartedAt || now - windowStartedAt >= windowMs) {
    await clearSecurityLimit(env, limitKey);
    return { allowed: true, retryAfterSeconds: 0 };
  }

  if (Number(row.action_count || 0) >= maximumFailures) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((windowStartedAt + windowMs - now) / 1000)
      )
    };
  }

  return { allowed: true, retryAfterSeconds: 0 };
}

async function recordFailure(
  env,
  limitKey,
  maximumFailures,
  windowMs,
  lockMs
) {
  const now = Date.now();
  const row = await readSecurityLimit(env, limitKey);
  const oldWindow = Number(row?.window_started_at || 0);
  const sameWindow =
    oldWindow > 0 && now - oldWindow < windowMs;
  const actionCount =
    (sameWindow ? Number(row?.action_count || 0) : 0) + 1;
  const windowStartedAt = sameWindow ? oldWindow : now;
  const lockedUntil =
    actionCount >= maximumFailures ? now + lockMs : 0;

  await saveSecurityLimit(env, limitKey, {
    actionCount,
    windowStartedAt,
    lockedUntil,
    lastActionAt: now
  });

  return {
    actionCount,
    lockedUntil,
    retryAfterSeconds:
      lockedUntil > now
        ? Math.ceil((lockedUntil - now) / 1000)
        : 0
  };
}

async function checkSmsLimit(env, limitKey) {
  const now = Date.now();
  const row = await readSecurityLimit(env, limitKey);

  if (!row) {
    return { allowed: true, retryAfterSeconds: 0 };
  }

  const windowStartedAt = Number(row.window_started_at || 0);
  const lastActionAt = Number(row.last_action_at || 0);

  if (!windowStartedAt || now - windowStartedAt >= SMS_LIMIT_WINDOW_MS) {
    await clearSecurityLimit(env, limitKey);
    return { allowed: true, retryAfterSeconds: 0 };
  }

  if (lastActionAt && now - lastActionAt < SMS_MIN_INTERVAL_MS) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((SMS_MIN_INTERVAL_MS - (now - lastActionAt)) / 1000)
      )
    };
  }

  if (Number(row.action_count || 0) >= SMS_MAX_PER_WINDOW) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil(
          (windowStartedAt + SMS_LIMIT_WINDOW_MS - now) / 1000
        )
      )
    };
  }

  return { allowed: true, retryAfterSeconds: 0 };
}

async function recordSmsRequest(env, limitKey) {
  const now = Date.now();
  const row = await readSecurityLimit(env, limitKey);
  const oldWindow = Number(row?.window_started_at || 0);
  const sameWindow =
    oldWindow > 0 && now - oldWindow < SMS_LIMIT_WINDOW_MS;

  await saveSecurityLimit(env, limitKey, {
    actionCount:
      (sameWindow ? Number(row?.action_count || 0) : 0) + 1,
    windowStartedAt: sameWindow ? oldWindow : now,
    lockedUntil: 0,
    lastActionAt: now
  });
}

function serializeUser(user) {
  return {
    id: user.id,
    phone: user.phone,
    username: user.username || null,
    full_name: user.full_name || null,
    avatar: user.avatar_data || "",
    last_username_change_at: user.last_username_change_at || null,
    is_admin: Boolean(user.is_admin),
    is_active: Boolean(user.is_active),
    must_change_password: Boolean(user.must_change_password),
    created_at: user.created_at,
    updated_at: user.updated_at
  };
}

async function findUserByPhone(env, phone) {
  await ensureProfileSchema(env);
  const database = requireDatabase(env);

  return database
    .prepare(`
      SELECT
        users.id,
        users.phone,
        users.username,
        users.full_name,
        users.is_admin,
        users.is_active,
        users.must_change_password,
        users.created_at,
        users.updated_at,
        COALESCE(user_profiles.avatar_data, '') AS avatar_data,
        user_profiles.last_username_change_at
      FROM users
      LEFT JOIN user_profiles
        ON user_profiles.user_id = users.id
      WHERE users.phone = ?
      LIMIT 1
    `)
    .bind(phone)
    .first();
}


async function findUserByIdentity(env, identity) {
  await ensureProfileSchema(env);
  const database = requireDatabase(env);
  const phone = normalizePhone(identity);
  const username = normalizeUsername(identity);

  if (!phone && !username) {
    return null;
  }

  return database
    .prepare(`
      SELECT
        users.id,
        users.phone,
        users.username,
        users.full_name,
        users.is_admin,
        users.is_active,
        users.must_change_password,
        users.created_at,
        users.updated_at,
        users.password_hash,
        users.password_updated_at,
        COALESCE(user_profiles.avatar_data, '') AS avatar_data,
        user_profiles.last_username_change_at
      FROM users
      LEFT JOIN user_profiles
        ON user_profiles.user_id = users.id
      WHERE users.phone = ?
         OR users.username = ? COLLATE NOCASE
      LIMIT 1
    `)
    .bind(phone || "", username || "")
    .first();
}

async function registerOrReactivateUser(env, phone) {
  const database = requireDatabase(env);

  await database
    .prepare(`
      INSERT INTO users (
        phone,
        is_active
      )
      VALUES (?, 1)

      ON CONFLICT(phone) DO UPDATE SET
        is_active = 1,
        updated_at = CURRENT_TIMESTAMP
    `)
    .bind(phone)
    .run();

  const user = await findUserByPhone(env, phone);

  if (!user) {
    throw new Error("ساخت حساب کاربری انجام نشد.");
  }

  return user;
}

async function createSession(env, userId) {
  const database = requireDatabase(env);

  await database
    .prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
        AND (
          revoked_at IS NOT NULL
          OR datetime(expires_at) <= datetime('now')
        )
    `)
    .bind(userId)
    .run();

  const token = createRandomToken(32);
  const tokenHash = await hash(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  await database
    .prepare(`
      INSERT INTO sessions (
        user_id,
        token_hash,
        expires_at
      )
      VALUES (?, ?, ?)
    `)
    .bind(userId, tokenHash, expiresAt)
    .run();

  return {
    token,
    expiresAt
  };
}

function readBearerToken(request) {
  const authorization =
    String(request.headers.get("Authorization") || "").trim();

  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

async function authenticateRequest(request, env, updateLastUsed = true) {
  const token = readBearerToken(request);

  if (!token) {
    return null;
  }

  await ensureProfileSchema(env);
  const database = requireDatabase(env);
  const tokenHash = await hash(token);

  const session = await database
    .prepare(`
      SELECT
        sessions.id AS session_id,
        sessions.expires_at,
        users.id,
        users.phone,
        users.username,
        users.full_name,
        users.is_admin,
        users.is_active,
        users.must_change_password,
        users.created_at,
        users.updated_at,
        COALESCE(user_profiles.avatar_data, '') AS avatar_data,
        user_profiles.last_username_change_at
      FROM sessions
      INNER JOIN users
        ON users.id = sessions.user_id
      LEFT JOIN user_profiles
        ON user_profiles.user_id = users.id
      WHERE sessions.token_hash = ?
        AND sessions.revoked_at IS NULL
        AND datetime(sessions.expires_at) > datetime('now')
        AND users.is_active = 1
      LIMIT 1
    `)
    .bind(tokenHash)
    .first();

  if (!session) {
    return null;
  }

  if (updateLastUsed) {
    await database
      .prepare(`
        UPDATE sessions
        SET last_used_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(session.session_id)
      .run();
  }

  return {
    sessionId: session.session_id,
    expiresAt: session.expires_at,
    user: serializeUser(session)
  };
}


function routeApiAction(request, url) {
  if (url.pathname !== "/api") {
    return { method: request.method, pathname: url.pathname };
  }

  const action = String(url.searchParams.get("action") || "")
    .trim()
    .toLowerCase();

  const routes = {
    health: { method: "GET", pathname: "/health" },
    presence_ping: { method: "POST", pathname: "/presence/ping" },
    request_code: { method: "POST", pathname: "/request-code" },
    verify_code: { method: "POST", pathname: "/verify-code" },
    register: { method: "POST", pathname: "/register" },
    login: { method: "POST", pathname: "/login" },
    reset_password: { method: "POST", pathname: "/reset-password" },
    change_password: { method: "POST", pathname: "/change-password" },
    update_profile: { method: "POST", pathname: "/profile" },
    set_username: { method: "POST", pathname: "/profile/username" },
    me: { method: "GET", pathname: "/me" },
    logout: { method: "POST", pathname: "/logout" },
    products: { method: "GET", pathname: "/products" },
    create_order: { method: "POST", pathname: "/orders" },
    orders_my: { method: "GET", pathname: "/orders/my" },
    track_order: { method: "POST", pathname: "/orders/track" },
    admin_login: { method: "POST", pathname: "/admin-login" },
    admin_users: { method: "GET", pathname: "/admin/users" },
    admin_user_status: { method: "POST", pathname: "/admin/users/status" },
    admin_user_revoke_sessions: { method: "POST", pathname: "/admin/users/revoke-sessions" },
    admin_user_temporary_password: { method: "POST", pathname: "/admin/users/temporary-password" },
    admin_products_sync: { method: "POST", pathname: "/admin/products/sync" },
    admin_orders: { method: "GET", pathname: "/admin/orders" },
    admin_order_status: { method: "POST", pathname: "/admin/orders/status" },
    admin_order_delete: { method: "POST", pathname: "/admin/orders/delete" }
  };

  const alias = action.replaceAll("-", "_");

  return routes[action] || routes[alias] || {
    method: request.method,
    pathname: url.pathname
  };
}

async function handleRequestCode(request, env) {
  const body = await request.json().catch(() => ({}));
  const phone = normalizePhone(body.phone);
  const purpose = normalizePurpose(body.purpose);

  if (!phone) {
    return json(env, 422, {
      ok: false,
      message: "شماره باید ۱۱ رقم و با 09 شروع شود."
    });
  }

  if (!String(env.OTP_SECRET || "").trim()) {
    return json(env, 500, {
      ok: false,
      message: "متغیر OTP_SECRET تنظیم نشده است."
    });
  }

  const smsLimitKey = `sms:${await hash(phone)}`;
  const smsLimit = await checkSmsLimit(env, smsLimitKey);

  if (!smsLimit.allowed) {
    return json(env, 429, {
      ok: false,
      message:
        `درخواست کد بیش از حد مجاز است. ${smsLimit.retryAfterSeconds} ثانیه دیگر تلاش کنید.`
    });
  }

  if (purpose === "reset") {
    const user = await findUserByPhone(env, phone);

    if (!user) {
      return json(env, 404, {
        ok: false,
        message: "حسابی با این شماره پیدا نشد."
      });
    }

    if (!user.is_active) {
      return json(env, 403, {
        ok: false,
        message: "این حساب غیرفعال شده است."
      });
    }
  }

  const otp = createOtp();
  const gateway = await sendSms(env, phone, otp, purpose);
  await recordSmsRequest(env, smsLimitKey);

  const verificationToken = await makeToken(env.OTP_SECRET, {
    phone,
    purpose,
    otpHash: await hash(`${otp}:${env.OTP_SECRET}`),
    expires: Date.now() + OTP_TTL_MS
  });

  return json(env, 200, {
    ok: true,
    message: "کد تأیید تا لحظه‌ای دیگر ارسال می‌شود.",
    verification_token: verificationToken,
    gateway_state: gateway.state || "Accepted",
    gateway_message_id: gateway.id || null
  });
}

async function handleVerifyCode(request, env) {
  const body = await request.json().catch(() => ({}));
  const phone = normalizePhone(body.phone);
  const purpose = normalizePurpose(body.purpose);
  const code = normalizeDigits(body.code).replace(/\D/g, "");

  if (!String(env.OTP_SECRET || "").trim()) {
    return json(env, 500, {
      ok: false,
      message: "متغیر OTP_SECRET تنظیم نشده است."
    });
  }

  const payload = await readToken(
    env.OTP_SECRET,
    body.verification_token
  );

  if (
    !phone ||
    !/^\d{6}$/.test(code) ||
    !payload ||
    payload.phone !== phone ||
    payload.purpose !== purpose ||
    payload.expires < Date.now()
  ) {
    return json(env, 401, {
      ok: false,
      message: "کد منقضی یا نامعتبر است."
    });
  }

  const otpLimitKey = `otp:${await hash(
    String(body.verification_token || "")
  )}`;
  const otpLimit = await checkFailureLimit(
    env,
    otpLimitKey,
    OTP_MAX_FAILURES,
    OTP_LIMIT_WINDOW_MS
  );

  if (!otpLimit.allowed) {
    return json(env, 429, {
      ok: false,
      message:
        `تلاش‌های کد تأیید بیش از حد مجاز است. ${otpLimit.retryAfterSeconds} ثانیه دیگر تلاش کنید.`
    });
  }

  const otpHash = await hash(`${code}:${env.OTP_SECRET}`);

  if (otpHash !== payload.otpHash) {
    await recordFailure(
      env,
      otpLimitKey,
      OTP_MAX_FAILURES,
      OTP_LIMIT_WINDOW_MS,
      OTP_LOCK_MS
    );

    return json(env, 422, {
      ok: false,
      message: "کد تأیید اشتباه است."
    });
  }

  await clearSecurityLimit(env, otpLimitKey);

  let user;

  if (purpose === "register") {
    user = await registerOrReactivateUser(env, phone);
  } else {
    user = await findUserByPhone(env, phone);

    if (!user) {
      return json(env, 404, {
        ok: false,
        message: "حسابی با این شماره پیدا نشد."
      });
    }

    if (!user.is_active) {
      return json(env, 403, {
        ok: false,
        message: "این حساب غیرفعال شده است."
      });
    }
  }

  const verifiedToken = await makeToken(env.OTP_SECRET, {
    user_id: user.id,
    phone,
    purpose,
    verified: true,
    expires: Date.now() + VERIFIED_TOKEN_TTL_MS
  });

  return json(env, 200, {
    ok: true,
    message:
      purpose === "register"
        ? "شماره تأیید شد؛ نام کاربری را تکمیل کنید."
        : "شماره برای بازیابی رمز تأیید شد.",
    verified_token: verifiedToken,
    user: serializeUser(user)
  });
}


async function handleRegister(request, env) {
  const body = await request.json().catch(() => ({}));
  const phone = normalizePhone(body.phone);
  const username = normalizeUsername(body.username);
  const password = normalizePassword(body.password);
  const passwordConfirm = normalizePassword(body.password_confirm);

  if (!phone) {
    return json(env, 422, {
      ok: false,
      message: "شماره موبایل معتبر نیست."
    });
  }

  if (!username) {
    return json(env, 422, {
      ok: false,
      message:
        "نام کاربری باید ۴ تا ۲۴ کاراکتر، با حرف انگلیسی شروع شود و فقط شامل حروف انگلیسی، عدد و _ باشد."
    });
  }

  if (username === "admin") {
    return json(env, 422, {
      ok: false,
      message: "نام کاربری admin برای مدیریت رزرو شده است."
    });
  }

  if (!validPassword(password)) {
    return json(env, 422, {
      ok: false,
      message:
        "رمز باید ۸ تا ۶۴ کاراکتر و شامل حرف بزرگ، حرف کوچک، عدد و علامت باشد و فاصله نداشته باشد."
    });
  }

  if (password !== passwordConfirm) {
    return json(env, 422, {
      ok: false,
      message: "تکرار رمز عبور یکسان نیست."
    });
  }

  const payload = await readToken(
    env.OTP_SECRET,
    body.verification_token
  );

  if (
    !payload ||
    payload.verified !== true ||
    payload.purpose !== "register" ||
    payload.phone !== phone ||
    payload.expires < Date.now()
  ) {
    return json(env, 401, {
      ok: false,
      message: "تأیید شماره منقضی یا نامعتبر است."
    });
  }

  const database = requireDatabase(env);
  const user = await findUserByPhone(env, phone);

  if (
    !user ||
    Number(user.id) !== Number(payload.user_id)
  ) {
    return json(env, 401, {
      ok: false,
      message: "حساب تأییدشده پیدا نشد."
    });
  }

  const existing = await database
    .prepare(`
      SELECT id
      FROM users
      WHERE username = ? COLLATE NOCASE
      LIMIT 1
    `)
    .bind(username)
    .first();

  if (existing && Number(existing.id) !== Number(user.id)) {
    return json(env, 409, {
      ok: false,
      message: "این نام کاربری قبلاً ثبت شده است."
    });
  }

  if (
    user.username &&
    user.username.toLowerCase() !== username
  ) {
    return json(env, 409, {
      ok: false,
      message: "نام کاربری این حساب قبلاً ثبت شده است."
    });
  }

  const passwordHash = await createPasswordHash(password);

  await database
    .prepare(`
      UPDATE users
      SET username = ?,
          full_name = ?,
          password_hash = ?,
          password_updated_at = CURRENT_TIMESTAMP,
          must_change_password = 0,
          is_active = 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND phone = ?
    `)
    .bind(
      username,
      username,
      passwordHash,
      user.id,
      phone
    )
    .run();

  await database
    .prepare(`
      UPDATE sessions
      SET revoked_at = CURRENT_TIMESTAMP
      WHERE user_id = ?
        AND revoked_at IS NULL
    `)
    .bind(user.id)
    .run();

  const savedUser = await findUserByPhone(env, phone);
  const session = await createSession(env, user.id);

  return json(env, 200, {
    ok: true,
    message: "ثبت‌نام با موفقیت انجام شد.",
    session_token: session.token,
    session_expires_at: session.expiresAt,
    user: serializeUser(savedUser)
  });
}

async function handlePasswordLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const identity = String(
    body.identity ||
    body.username ||
    ""
  ).trim();
  const password = normalizePassword(body.password);

  if (!identity || !password) {
    return json(env, 422, {
      ok: false,
      message: "نام کاربری/شماره و رمز را وارد کنید."
    });
  }

  const loginLimitKey = `login:${await hash(
    identity.toLowerCase()
  )}`;
  const loginLimit = await checkFailureLimit(
    env,
    loginLimitKey,
    LOGIN_MAX_FAILURES,
    LOGIN_LIMIT_WINDOW_MS
  );

  if (!loginLimit.allowed) {
    return json(env, 429, {
      ok: false,
      message:
        `تلاش‌های ورود بیش از حد مجاز است. ${loginLimit.retryAfterSeconds} ثانیه دیگر تلاش کنید.`
    });
  }

  const user = await findUserByIdentity(env, identity);

  const passwordIsValid = Boolean(
    user &&
    user.password_hash &&
    await verifyPassword(password, user.password_hash)
  );

  if (!passwordIsValid) {
    await recordFailure(
      env,
      loginLimitKey,
      LOGIN_MAX_FAILURES,
      LOGIN_LIMIT_WINDOW_MS,
      LOGIN_LOCK_MS
    );

    return json(env, 401, {
      ok: false,
      message: "نام کاربری، شماره موبایل یا رمز عبور اشتباه است."
    });
  }

  await clearSecurityLimit(env, loginLimitKey);

  if (!user.is_active) {
    return json(env, 403, {
      ok: false,
      message: "حساب کاربری شما مسدود شده است."
    });
  }

  const session = await createSession(env, user.id);

  return json(env, 200, {
    ok: true,
    message: "ورود با موفقیت انجام شد.",
    session_token: session.token,
    session_expires_at: session.expiresAt,
    user: serializeUser(user)
  });
}


async function handleAdminLogin(request, env) {
  const response = await handlePasswordLogin(request, env);

  if (!response.ok) {
    return response;
  }

  const payload = await response.json().catch(() => ({}));

  if (!payload.user || !payload.user.is_admin) {
    if (payload.session_token) {
      const database = requireDatabase(env);
      await database
        .prepare(`
          UPDATE sessions
          SET revoked_at = CURRENT_TIMESTAMP
          WHERE token_hash = ?
        `)
        .bind(await hash(payload.session_token))
        .run();
    }

    return json(env, 403, {
      ok: false,
      message: "این حساب دسترسی مدیریت ندارد."
    });
  }

  return json(env, 200, {
    ...payload,
    message: "ورود مدیر با موفقیت انجام شد."
  });
}

async function handleResetPassword(request, env) {
  const body = await request.json().catch(() => ({}));
  const phone = normalizePhone(body.phone);
  const password = normalizePassword(body.password);
  const passwordConfirm = normalizePassword(body.password_confirm);

  if (!phone) {
    return json(env, 422, {
      ok: false,
      message: "شماره موبایل معتبر نیست."
    });
  }

  if (!validPassword(password)) {
    return json(env, 422, {
      ok: false,
      message:
        "رمز باید ۸ تا ۶۴ کاراکتر و شامل حرف بزرگ، حرف کوچک، عدد و علامت باشد و فاصله نداشته باشد."
    });
  }

  if (password !== passwordConfirm) {
    return json(env, 422, {
      ok: false,
      message: "تکرار رمز عبور یکسان نیست."
    });
  }

  const payload = await readToken(
    env.OTP_SECRET,
    body.verification_token
  );

  if (
    !payload ||
    payload.verified !== true ||
    payload.purpose !== "reset" ||
    payload.phone !== phone ||
    payload.expires < Date.now()
  ) {
    return json(env, 401, {
      ok: false,
      message: "تأیید بازیابی منقضی یا نامعتبر است."
    });
  }

  const user = await findUserByPhone(env, phone);

  if (
    !user ||
    Number(user.id) !== Number(payload.user_id)
  ) {
    return json(env, 404, {
      ok: false,
      message: "حسابی با این شماره پیدا نشد."
    });
  }

  if (!user.is_active) {
    return json(env, 403, {
      ok: false,
      message: "این حساب غیرفعال شده است."
    });
  }

  const database = requireDatabase(env);
  const passwordHash = await createPasswordHash(password);

  await database
    .prepare(`
      UPDATE users
      SET password_hash = ?,
          password_updated_at = CURRENT_TIMESTAMP,
          must_change_password = 0,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(passwordHash, user.id)
    .run();

  await database
    .prepare(`
      UPDATE sessions
      SET revoked_at = CURRENT_TIMESTAMP
      WHERE user_id = ?
        AND revoked_at IS NULL
    `)
    .bind(user.id)
    .run();

  return json(env, 200, {
    ok: true,
    message: "رمز عبور با موفقیت تغییر کرد."
  });
}


function normalizeUserId(value) {
  const userId = Number(normalizeDigits(value));

  return Number.isInteger(userId) && userId > 0
    ? userId
    : 0;
}

async function requireAdminAuthentication(request, env) {
  const authentication = await authenticateRequest(request, env, true);

  if (!authentication || !authentication.user.is_admin) {
    return null;
  }

  return authentication;
}

async function findUserForAdministration(env, userId) {
  const database = requireDatabase(env);

  return database
    .prepare(`
      SELECT
        id,
        phone,
        username,
        full_name,
        is_admin,
        is_active,
        must_change_password,
        password_hash IS NOT NULL AS password_set,
        password_updated_at,
        created_at,
        updated_at
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
    .bind(userId)
    .first();
}

function serializeAdminUser(user) {
  return {
    id: Number(user.id),
    phone: user.phone,
    username: user.username || null,
    full_name: user.full_name || null,
    is_admin: Boolean(user.is_admin),
    is_active: Boolean(user.is_active),
    must_change_password: Boolean(user.must_change_password),
    password_set: Boolean(user.password_set),
    password_updated_at: user.password_updated_at || null,
    active_sessions: Number(user.active_sessions || 0),
    created_at: user.created_at,
    updated_at: user.updated_at
  };
}

async function handleAdminUsers(request, env) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const database = requireDatabase(env);

  const result = await database
    .prepare(`
      SELECT
        users.id,
        users.phone,
        users.username,
        users.full_name,
        users.is_admin,
        users.is_active,
        users.must_change_password,
        users.password_hash IS NOT NULL AS password_set,
        users.password_updated_at,
        users.created_at,
        users.updated_at,
        (
          SELECT COUNT(*)
          FROM sessions
          WHERE sessions.user_id = users.id
            AND sessions.revoked_at IS NULL
            AND datetime(sessions.expires_at) > datetime('now')
        ) AS active_sessions
      FROM users
      ORDER BY users.is_admin DESC, users.id ASC
    `)
    .all();

  return json(env, 200, {
    ok: true,
    users: (result.results || []).map(serializeAdminUser),
    admin_user_id: authentication.user.id
  });
}

async function handleAdminUserStatus(request, env) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const body = await request.json().catch(() => ({}));
  const userId = normalizeUserId(body.user_id);
  const isActive =
    body.is_active === true ||
    body.is_active === 1 ||
    body.is_active === "1";

  if (!userId) {
    return json(env, 422, {
      ok: false,
      message: "شناسه کاربر معتبر نیست."
    });
  }

  const target = await findUserForAdministration(env, userId);

  if (!target) {
    return json(env, 404, {
      ok: false,
      message: "کاربر پیدا نشد."
    });
  }

  if (target.is_admin) {
    return json(env, 409, {
      ok: false,
      message: "وضعیت حساب مدیر از این بخش قابل تغییر نیست."
    });
  }

  const database = requireDatabase(env);

  await database
    .prepare(`
      UPDATE users
      SET is_active = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(isActive ? 1 : 0, userId)
    .run();

  if (!isActive) {
    await database
      .prepare(`
        UPDATE sessions
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
          AND revoked_at IS NULL
      `)
      .bind(userId)
      .run();
  }

  const saved = await findUserForAdministration(env, userId);

  return json(env, 200, {
    ok: true,
    message: isActive
      ? "حساب کاربر فعال شد."
      : "حساب کاربر غیرفعال و نشست‌هایش بسته شد.",
    user: serializeAdminUser(saved)
  });
}

async function handleAdminRevokeSessions(request, env) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const body = await request.json().catch(() => ({}));
  const userId = normalizeUserId(body.user_id);

  if (!userId) {
    return json(env, 422, {
      ok: false,
      message: "شناسه کاربر معتبر نیست."
    });
  }

  const target = await findUserForAdministration(env, userId);

  if (!target) {
    return json(env, 404, {
      ok: false,
      message: "کاربر پیدا نشد."
    });
  }

  if (target.is_admin) {
    return json(env, 409, {
      ok: false,
      message: "نشست مدیر از بخش مدیریت کاربران بسته نمی‌شود."
    });
  }

  const database = requireDatabase(env);

  const result = await database
    .prepare(`
      UPDATE sessions
      SET revoked_at = CURRENT_TIMESTAMP
      WHERE user_id = ?
        AND revoked_at IS NULL
    `)
    .bind(userId)
    .run();

  return json(env, 200, {
    ok: true,
    message: "همه نشست‌های فعال کاربر بسته شد.",
    revoked_sessions: Number(result.meta?.changes || 0)
  });
}

async function handleAdminTemporaryPassword(request, env) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const body = await request.json().catch(() => ({}));
  const userId = normalizeUserId(body.user_id);
  const password = normalizePassword(body.temporary_password);
  const passwordConfirm =
    normalizePassword(body.password_confirm);

  if (!userId) {
    return json(env, 422, {
      ok: false,
      message: "شناسه کاربر معتبر نیست."
    });
  }

  if (!validPassword(password)) {
    return json(env, 422, {
      ok: false,
      message:
        "رمز موقت باید ۸ تا ۶۴ کاراکتر و شامل حرف بزرگ، حرف کوچک، عدد و علامت باشد و فاصله نداشته باشد."
    });
  }

  if (password !== passwordConfirm) {
    return json(env, 422, {
      ok: false,
      message: "تکرار رمز موقت یکسان نیست."
    });
  }

  const target = await findUserForAdministration(env, userId);

  if (!target) {
    return json(env, 404, {
      ok: false,
      message: "کاربر پیدا نشد."
    });
  }

  if (target.is_admin) {
    return json(env, 409, {
      ok: false,
      message:
        "رمز مدیر فقط از مسیر بازیابی پیامکی خودش تغییر می‌کند."
    });
  }

  const database = requireDatabase(env);
  const passwordHash = await createPasswordHash(password);

  await database
    .prepare(`
      UPDATE users
      SET password_hash = ?,
          password_updated_at = CURRENT_TIMESTAMP,
          must_change_password = 1,
          is_active = 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(passwordHash, userId)
    .run();

  await database
    .prepare(`
      UPDATE sessions
      SET revoked_at = CURRENT_TIMESTAMP
      WHERE user_id = ?
        AND revoked_at IS NULL
    `)
    .bind(userId)
    .run();

  return json(env, 200, {
    ok: true,
    message:
      "رمز موقت ثبت شد؛ کاربر در ورود بعدی باید آن را تغییر دهد."
  });
}

async function handleChangePassword(request, env) {
  const authentication =
    await authenticateRequest(request, env, true);

  if (!authentication) {
    return json(env, 401, {
      ok: false,
      message: "نشست ورود نامعتبر یا منقضی شده است."
    });
  }

  const body = await request.json().catch(() => ({}));
  const currentPassword =
    normalizePassword(body.current_password);
  const newPassword =
    normalizePassword(body.new_password);
  const newPasswordConfirm =
    normalizePassword(body.new_password_confirm);
  const forcedPasswordChange =
    Boolean(authentication.user.must_change_password);

  if (!validPassword(newPassword)) {
    return json(env, 422, {
      ok: false,
      message:
        "رمز جدید باید ۸ تا ۶۴ کاراکتر و شامل حرف بزرگ، حرف کوچک، عدد و علامت باشد و فاصله نداشته باشد."
    });
  }

  if (newPassword !== newPasswordConfirm) {
    return json(env, 422, {
      ok: false,
      message: "تکرار رمز جدید یکسان نیست."
    });
  }

  const user = await findUserByIdentity(
    env,
    authentication.user.phone
  );

  if (!user || !user.password_hash) {
    return json(env, 404, {
      ok: false,
      message: "حساب کاربری پیدا نشد."
    });
  }

  if (forcedPasswordChange) {
    if (await verifyPassword(newPassword, user.password_hash)) {
      return json(env, 422, {
        ok: false,
        message: "رمز جدید باید با رمز موقت متفاوت باشد."
      });
    }
  } else {
    if (!currentPassword) {
      return json(env, 422, {
        ok: false,
        message: "رمز فعلی را وارد کنید."
      });
    }

    if (!(await verifyPassword(currentPassword, user.password_hash))) {
      return json(env, 401, {
        ok: false,
        message: "رمز فعلی نادرست است."
      });
    }
  }

  const database = requireDatabase(env);
  const passwordHash = await createPasswordHash(newPassword);

  await database
    .prepare(`
      UPDATE users
      SET password_hash = ?,
          password_updated_at = CURRENT_TIMESTAMP,
          must_change_password = 0,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(passwordHash, authentication.user.id)
    .run();

  await database
    .prepare(`
      UPDATE sessions
      SET revoked_at = CURRENT_TIMESTAMP
      WHERE user_id = ?
        AND id <> ?
        AND revoked_at IS NULL
    `)
    .bind(
      authentication.user.id,
      authentication.sessionId
    )
    .run();

  const savedUser = await findUserByPhone(
    env,
    authentication.user.phone
  );

  return json(env, 200, {
    ok: true,
    message: "رمز عبور با موفقیت تغییر کرد.",
    user: serializeUser(savedUser)
  });
}

async function handleUpdateProfile(request, env) {
  const authentication = await authenticateRequest(request, env, true);

  if (!authentication) {
    return json(env, 401, {
      ok: false,
      message: "نشست ورود نامعتبر یا منقضی شده است."
    });
  }

  const body = await request.json().catch(() => ({}));
  const currentUsername = String(
    authentication.user.username || ""
  ).trim().toLowerCase();
  const requestedUsername = normalizeUsername(
    body.username ?? currentUsername
  );
  const avatarWasProvided = Object.prototype.hasOwnProperty.call(
    body,
    "avatar"
  );
  const requestedAvatar = avatarWasProvided
    ? normalizeAvatarData(body.avatar)
    : authentication.user.avatar || "";

  if (!requestedUsername) {
    return json(env, 422, {
      ok: false,
      message:
        "نام کاربری باید ۴ تا ۲۴ کاراکتر، با حرف انگلیسی شروع شود و فقط شامل حروف انگلیسی، عدد و _ باشد."
    });
  }

  if (requestedUsername === "admin") {
    return json(env, 422, {
      ok: false,
      message: "نام کاربری admin برای مدیریت رزرو شده است."
    });
  }

  if (requestedAvatar === null) {
    return json(env, 422, {
      ok: false,
      message:
        "تصویر پروفایل معتبر نیست یا حجم آن بیش از حد مجاز است."
    });
  }

  await ensureProfileSchema(env);
  const database = requireDatabase(env);
  const usernameChanged =
    requestedUsername !== currentUsername;
  const avatarChanged =
    requestedAvatar !== String(authentication.user.avatar || "");

  if (usernameChanged) {
    const existing = await database
      .prepare(`
        SELECT id
        FROM users
        WHERE username = ? COLLATE NOCASE
        LIMIT 1
      `)
      .bind(requestedUsername)
      .first();

    if (
      existing &&
      Number(existing.id) !== Number(authentication.user.id)
    ) {
      return json(env, 409, {
        ok: false,
        message: "این نام کاربری قبلاً ثبت شده است."
      });
    }

    const lastChangedAt = Date.parse(
      String(
        authentication.user.last_username_change_at || ""
      )
        .replace(" ", "T")
        .replace(/Z?$/, "Z")
    );

    if (
      Number.isFinite(lastChangedAt) &&
      Date.now() - lastChangedAt < USERNAME_CHANGE_INTERVAL_MS
    ) {
      const nextAllowed = new Date(
        lastChangedAt + USERNAME_CHANGE_INTERVAL_MS
      ).toLocaleDateString("fa-IR");

      return json(env, 409, {
        ok: false,
        message:
          `تغییر نام کاربری هر ۳۰ روز یک‌بار مجاز است. تاریخ بعدی: ${nextAllowed}`
      });
    }
  }

  if (!usernameChanged && !avatarChanged) {
    return json(env, 200, {
      ok: true,
      message: "تغییری برای ذخیره وجود نداشت.",
      user: authentication.user
    });
  }

  const statements = [];

  if (usernameChanged) {
    statements.push(
      database
        .prepare(`
          UPDATE users
          SET username = ?,
              full_name = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(
          requestedUsername,
          requestedUsername,
          authentication.user.id
        )
    );
  }

  statements.push(
    database
      .prepare(`
        INSERT INTO user_profiles (
          user_id,
          avatar_data,
          last_username_change_at,
          created_at,
          updated_at
        )
        VALUES (
          ?,
          ?,
          CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END,
          CURRENT_TIMESTAMP,
          CURRENT_TIMESTAMP
        )
        ON CONFLICT(user_id) DO UPDATE SET
          avatar_data = excluded.avatar_data,
          last_username_change_at =
            CASE
              WHEN ? = 1 THEN CURRENT_TIMESTAMP
              ELSE user_profiles.last_username_change_at
            END,
          updated_at = CURRENT_TIMESTAMP
      `)
      .bind(
        authentication.user.id,
        requestedAvatar,
        usernameChanged ? 1 : 0,
        usernameChanged ? 1 : 0
      )
  );

  await database.batch(statements);

  const savedUser = await findUserByPhone(
    env,
    authentication.user.phone
  );

  return json(env, 200, {
    ok: true,
    message: "پروفایل با موفقیت ذخیره شد.",
    user: serializeUser(savedUser)
  });
}


async function handleSetUsername(request, env) {
  return handleUpdateProfile(request, env);
}

async function handleMe(request, env) {
  const authentication = await authenticateRequest(request, env, true);

  if (!authentication) {
    return json(env, 401, {
      ok: false,
      message: "نشست ورود نامعتبر یا منقضی شده است."
    });
  }

  return json(env, 200, {
    ok: true,
    user: authentication.user,
    session_expires_at: authentication.expiresAt
  });
}

async function handleLogout(request, env) {
  const authentication = await authenticateRequest(request, env, false);

  if (!authentication) {
    return json(env, 401, {
      ok: false,
      message: "نشست ورود نامعتبر یا منقضی شده است."
    });
  }

  const database = requireDatabase(env);

  await database
    .prepare(`
      UPDATE sessions
      SET revoked_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `)
    .bind(authentication.sessionId)
    .run();

  return json(env, 200, {
    ok: true,
    message: "با موفقیت از حساب خارج شدید."
  });
}


function normalizeOrderText(value, maxLength = 500) {
  return String(value || "")
    .normalize("NFKC")
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/[ \t]+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function normalizeMultilineOrderText(value, maxLength = 500) {
  return String(value || "")
    .normalize("NFKC")
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function normalizePositiveInteger(value, maximum = 1000000) {
  const number = Number(normalizeDigits(value));

  return Number.isInteger(number) && number > 0 && number <= maximum
    ? number
    : 0;
}

function normalizeMoney(value) {
  const number = Number(value);

  return Number.isInteger(number) && number >= 0 && number <= 1000000000000
    ? number
    : -1;
}

const ORDER_STATUS_VALUES = new Set([
  "new",
  "processing",
  "shipped",
  "delivered",
  "cancelled"
]);

function normalizeOrderStatus(value, fallback = "") {
  const status = String(value || "").trim().toLowerCase();

  const aliases = {
    pending: "new",
    confirmed: "processing",
    preparing: "processing",
    sent: "shipped",
    completed: "delivered",
    complete: "delivered",
    canceled: "cancelled"
  };

  const normalized = aliases[status] || status;

  return ORDER_STATUS_VALUES.has(normalized)
    ? normalized
    : fallback;
}

function orderStatusForDatabase(status) {
  return status === "new" ? "pending" : status;
}

function createOrderNumber() {
  const now = new Date();
  const date = [
    now.getUTCFullYear(),
    String(now.getUTCMonth() + 1).padStart(2, "0"),
    String(now.getUTCDate()).padStart(2, "0")
  ].join("");

  const random = createRandomToken(8)
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, 8)
    .toUpperCase();

  return `DC-${date}-${random}`;
}

function serializeCatalogProduct(product) {
  return {
    id: Number(product.id),
    name: product.name,
    price: Number(product.price || 0),
    oldPrice: Number(product.original_price || 0),
    stock: Number(product.stock || 0),
    is_active: Boolean(product.is_active),
    updated_at: product.updated_at
  };
}

function serializeOrder(order, items = []) {
  return {
    id: Number(order.id),
    code: order.order_number,
    username: order.username || null,
    customer_name: order.receiver_name,
    phone: order.receiver_phone || order.customer_phone,
    province: order.province || "",
    city: order.city || "",
    postal_code: order.postal_code || "",
    address: order.shipping_address || "",
    delivery: order.delivery === "pickup" ? "pickup" : "shipping",
    note: order.note || "",
    total: Number(order.total_amount || 0),
    status: normalizeOrderStatus(order.status, "new"),
    payment_status: order.payment_status || "unpaid",
    payment_reference: order.payment_reference || null,
    created_at: order.created_at,
    updated_at: order.updated_at,
    items: items.map(item => ({
      product_id: Number(item.product_id),
      name: item.product_title,
      quantity: Number(item.quantity),
      unit_price: Number(item.unit_price),
      original_price: Number(item.unit_price),
      discount: 0,
      line_total: Number(item.line_total)
    }))
  };
}

async function getOrderItems(env, orderIds) {
  const ids = [...new Set(
    (orderIds || [])
      .map(value => Number(value))
      .filter(value => Number.isInteger(value) && value > 0)
  )];

  if (!ids.length) {
    return new Map();
  }

  const database = requireDatabase(env);
  const placeholders = ids.map(() => "?").join(",");

  const result = await database
    .prepare(`
      SELECT
        id,
        order_id,
        product_id,
        product_title,
        unit_price,
        quantity,
        line_total,
        created_at
      FROM order_items
      WHERE order_id IN (${placeholders})
      ORDER BY id ASC
    `)
    .bind(...ids)
    .all();

  const grouped = new Map();

  for (const item of result.results || []) {
    const orderId = Number(item.order_id);

    if (!grouped.has(orderId)) {
      grouped.set(orderId, []);
    }

    grouped.get(orderId).push(item);
  }

  return grouped;
}

async function getOrderById(env, orderId) {
  const database = requireDatabase(env);

  const order = await database
    .prepare(`
      SELECT
        orders.*,
        users.username
      FROM orders
      LEFT JOIN users
        ON users.id = orders.user_id
      WHERE orders.id = ?
      LIMIT 1
    `)
    .bind(orderId)
    .first();

  if (!order) {
    return null;
  }

  const items = await getOrderItems(env, [order.id]);

  return serializeOrder(order, items.get(Number(order.id)) || []);
}

async function restoreInventoryForItems(env, items) {
  const database = requireDatabase(env);
  const validItems = (items || []).filter(item =>
    Number.isInteger(Number(item.product_id)) &&
    Number(item.product_id) > 0 &&
    Number.isInteger(Number(item.quantity)) &&
    Number(item.quantity) > 0
  );
  const statements = [];

  for (const item of validItems) {
    statements.push(
      database
        .prepare(`
          UPDATE catalog_products
          SET stock = stock + ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(Number(item.quantity), Number(item.product_id))
    );

    statements.push(
      database
        .prepare(`
          UPDATE products
          SET stock = stock + ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(Number(item.quantity), Number(item.product_id))
    );
  }

  if (statements.length) {
    await database.batch(statements);
  }
}

async function reserveInventoryForItems(env, items) {
  const database = requireDatabase(env);
  const validItems = (items || []).filter(item =>
    Number.isInteger(Number(item.product_id)) &&
    Number(item.product_id) > 0 &&
    Number.isInteger(Number(item.quantity)) &&
    Number(item.quantity) > 0
  );

  if (!validItems.length) {
    return { ok: false, reserved: [] };
  }

  const results = await database.batch(
    validItems.map(item =>
      database
        .prepare(`
          UPDATE catalog_products
          SET stock = stock - ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
            AND is_active = 1
            AND stock >= ?
        `)
        .bind(
          Number(item.quantity),
          Number(item.product_id),
          Number(item.quantity)
        )
    )
  );

  const reserved = [];

  for (let index = 0; index < results.length; index++) {
    if (Number(results[index]?.meta?.changes || 0) === 1) {
      reserved.push(validItems[index]);
    }
  }

  if (reserved.length !== validItems.length) {
    await restoreInventoryForItems(env, reserved);
    return { ok: false, reserved: [] };
  }

  await database.batch(
    reserved.map(item =>
      database
        .prepare(`
          UPDATE products
          SET stock = CASE
                WHEN stock >= ? THEN stock - ?
                ELSE 0
              END,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
        .bind(
          Number(item.quantity),
          Number(item.quantity),
          Number(item.product_id)
        )
    )
  );

  return { ok: true, reserved };
}

async function handlePublicProducts(request, env) {
  const database = requireDatabase(env);

  const result = await database
    .prepare(`
      SELECT
        id,
        name,
        price,
        original_price,
        stock,
        is_active,
        updated_at
      FROM catalog_products
      WHERE is_active = 1
      ORDER BY id ASC
    `)
    .all();

  return json(env, 200, {
    ok: true,
    products: (result.results || []).map(serializeCatalogProduct)
  });
}

async function handleAdminProductsSync(request, env) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const body = await request.json().catch(() => ({}));
  const source = Array.isArray(body.products) ? body.products : [];

  if (!source.length || source.length > 300) {
    return json(env, 422, {
      ok: false,
      message: "فهرست محصولات معتبر نیست."
    });
  }

  const products = [];
  const seen = new Set();

  for (const row of source) {
    const id = normalizePositiveInteger(row.id, Number.MAX_SAFE_INTEGER);
    const name = normalizeOrderText(row.name, 120);
    const price = normalizeMoney(
      row.sale_price ?? row.price
    );
    const originalPrice = normalizeMoney(
      row.oldPrice ?? row.original_price ?? row.price
    );
    const stock = Number(normalizeDigits(row.stock));

    if (
      !id ||
      seen.has(id) ||
      name.length < 2 ||
      price < 0 ||
      originalPrice < 0 ||
      !Number.isInteger(stock) ||
      stock < 0 ||
      stock > 1000000
    ) {
      return json(env, 422, {
        ok: false,
        message: "اطلاعات یکی از محصولات معتبر نیست."
      });
    }

    seen.add(id);
    products.push({
      id,
      name,
      price,
      originalPrice: Math.max(price, originalPrice),
      stock
    });
  }

  const database = requireDatabase(env);
  const statements = [
    database.prepare(`
      UPDATE catalog_products
      SET is_active = 0,
          updated_at = CURRENT_TIMESTAMP
    `),
    database.prepare(`
      UPDATE products
      SET is_active = 0,
          updated_at = CURRENT_TIMESTAMP
    `)
  ];

  for (const product of products) {
    statements.push(
      database
        .prepare(`
          INSERT INTO catalog_products (
            id,
            name,
            price,
            original_price,
            stock,
            is_active,
            updated_at
          )
          VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)

          ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            price = excluded.price,
            original_price = excluded.original_price,
            stock = excluded.stock,
            is_active = 1,
            updated_at = CURRENT_TIMESTAMP
        `)
        .bind(
          product.id,
          product.name,
          product.price,
          product.originalPrice,
          product.stock
        )
    );

    statements.push(
      database
        .prepare(`
          INSERT INTO products (
            id,
            title,
            slug,
            description,
            price,
            compare_at_price,
            stock,
            image_url,
            is_active,
            created_at,
            updated_at
          )
          VALUES (
            ?, ?, ?, '', ?, ?, ?, NULL, 1,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
          )

          ON CONFLICT(id) DO UPDATE SET
            title = excluded.title,
            price = excluded.price,
            compare_at_price = excluded.compare_at_price,
            stock = excluded.stock,
            is_active = 1,
            updated_at = CURRENT_TIMESTAMP
        `)
        .bind(
          product.id,
          product.name,
          `catalog-${product.id}`,
          product.price,
          product.originalPrice,
          product.stock
        )
    );
  }

  await database.batch(statements);

  return json(env, 200, {
    ok: true,
    message: "محصولات در دیتابیس همگام شدند.",
    synced_products: products.length
  });
}

async function handleCreateOrder(request, env) {
  const authentication =
    await authenticateRequest(request, env, true);

  if (!authentication) {
    return json(env, 401, {
      ok: false,
      message: "نشست ورود نامعتبر یا منقضی شده است."
    });
  }

  if (authentication.user.must_change_password) {
    return json(env, 403, {
      ok: false,
      message: "ابتدا رمز موقت حساب را تغییر دهید."
    });
  }

  const body = await request.json().catch(() => ({}));
  const customerName = normalizeOrderText(body.customer_name, 70);
  const province = normalizeOrderText(body.province, 40);
  const city = normalizeOrderText(body.city, 40);
  const postalCode = normalizeDigits(body.postal_code)
    .replace(/\D/g, "")
    .slice(0, 20);
  const address = normalizeMultilineOrderText(body.address, 500);
  const delivery =
    String(body.delivery || "").trim() === "pickup"
      ? "pickup"
      : "shipping";
  const note = normalizeMultilineOrderText(body.note, 500);
  const requestedItems = Array.isArray(body.items) ? body.items : [];

  if (
    customerName.length < 2 ||
    province.length < 2 ||
    city.length < 2 ||
    postalCode.length < 5 ||
    address.length < 5 ||
    requestedItems.length < 1 ||
    requestedItems.length > 50
  ) {
    return json(env, 422, {
      ok: false,
      message: "اطلاعات سفارش کامل یا معتبر نیست."
    });
  }

  const itemQuantities = new Map();

  for (const row of requestedItems) {
    const productId = normalizePositiveInteger(
      row.product_id,
      Number.MAX_SAFE_INTEGER
    );
    const quantity = normalizePositiveInteger(row.quantity, 1000);

    if (!productId || !quantity) {
      return json(env, 422, {
        ok: false,
        message: "تعداد یا شناسه یکی از محصولات معتبر نیست."
      });
    }

    itemQuantities.set(
      productId,
      (itemQuantities.get(productId) || 0) + quantity
    );
  }

  const productIds = [...itemQuantities.keys()];
  const placeholders = productIds.map(() => "?").join(",");
  const database = requireDatabase(env);

  const productResult = await database
    .prepare(`
      SELECT
        id,
        name,
        price,
        original_price,
        stock,
        is_active
      FROM catalog_products
      WHERE id IN (${placeholders})
    `)
    .bind(...productIds)
    .all();

  const productMap = new Map(
    (productResult.results || []).map(product => [
      Number(product.id),
      product
    ])
  );

  const trustedItems = [];

  for (const productId of productIds) {
    const product = productMap.get(productId);
    const quantity = itemQuantities.get(productId);

    if (
      !product ||
      !product.is_active ||
      Number(product.stock) < quantity
    ) {
      return json(env, 409, {
        ok: false,
        message: "موجودی یا قیمت یکی از محصولات تغییر کرده است."
      });
    }

    trustedItems.push({
      product_id: productId,
      product_title: product.name,
      quantity,
      unit_price: Number(product.price),
      compare_at_price: Number(
        product.original_price || product.price
      ),
      stock_after_order: Math.max(
        0,
        Number(product.stock) - quantity
      ),
      line_total: Number(product.price) * quantity
    });
  }

  const total = trustedItems.reduce(
    (sum, item) => sum + item.line_total,
    0
  );

  if (!Number.isSafeInteger(total) || total < 0) {
    return json(env, 422, {
      ok: false,
      message: "مبلغ سفارش معتبر نیست."
    });
  }

  const reservation = await reserveInventoryForItems(
    env,
    trustedItems
  );

  if (!reservation.ok) {
    return json(env, 409, {
      ok: false,
      message: "موجودی یکی از محصولات به‌تازگی تمام شده است."
    });
  }

  const orderNumber = createOrderNumber();

  try {
    const statements = [];

    for (const item of trustedItems) {
      statements.push(
        database
          .prepare(`
            INSERT INTO products (
              id,
              title,
              slug,
              description,
              price,
              compare_at_price,
              stock,
              image_url,
              is_active,
              created_at,
              updated_at
            )
            VALUES (
              ?, ?, ?, '', ?, ?, ?, NULL, 1,
              CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )

            ON CONFLICT(id) DO UPDATE SET
              title = excluded.title,
              price = excluded.price,
              compare_at_price = excluded.compare_at_price,
              stock = excluded.stock,
              is_active = 1,
              updated_at = CURRENT_TIMESTAMP
          `)
          .bind(
            item.product_id,
            item.product_title,
            `catalog-${item.product_id}`,
            item.unit_price,
            item.compare_at_price,
            item.stock_after_order
          )
      );
    }

    statements.push(
      database
        .prepare(`
          INSERT INTO orders (
            order_number,
            user_id,
            customer_phone,
            receiver_name,
            receiver_phone,
            shipping_address,
            postal_code,
            total_amount,
            status,
            payment_status,
            province,
            city,
            delivery,
            note,
            inventory_restored,
            created_at,
            updated_at
          )
          VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?,
            'pending', 'unpaid', ?, ?, ?, ?, 0,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
          )
        `)
        .bind(
          orderNumber,
          authentication.user.id,
          authentication.user.phone,
          customerName,
          authentication.user.phone,
          address,
          postalCode,
          total,
          province,
          city,
          delivery,
          note
        )
    );

    for (const item of trustedItems) {
      statements.push(
        database
          .prepare(`
            INSERT INTO order_items (
              order_id,
              product_id,
              product_title,
              unit_price,
              quantity,
              line_total,
              created_at
            )
            VALUES (
              (
                SELECT id
                FROM orders
                WHERE order_number = ?
                LIMIT 1
              ),
              ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
            )
          `)
          .bind(
            orderNumber,
            item.product_id,
            item.product_title,
            item.unit_price,
            item.quantity,
            item.line_total
          )
      );
    }

    await database.batch(statements);
  } catch (error) {
    await restoreInventoryForItems(env, trustedItems);
    throw error;
  }

  const saved = await database
    .prepare(`
      SELECT id
      FROM orders
      WHERE order_number = ?
      LIMIT 1
    `)
    .bind(orderNumber)
    .first();

  const order = saved
    ? await getOrderById(env, saved.id)
    : null;

  if (!order) {
    return json(env, 500, {
      ok: false,
      message: "سفارش ذخیره شد ولی دریافت اطلاعات آن ممکن نشد."
    });
  }

  return json(env, 201, {
    ok: true,
    message: "سفارش با موفقیت در دیتابیس ثبت شد.",
    tracking_code: order.code,
    order
  });
}

async function handleMyOrders(request, env) {
  const authentication =
    await authenticateRequest(request, env, true);

  if (!authentication) {
    return json(env, 401, {
      ok: false,
      message: "نشست ورود نامعتبر یا منقضی شده است."
    });
  }

  const database = requireDatabase(env);
  const result = await database
    .prepare(`
      SELECT
        orders.*,
        users.username
      FROM orders
      LEFT JOIN users
        ON users.id = orders.user_id
      WHERE orders.user_id = ?
      ORDER BY datetime(orders.created_at) DESC, orders.id DESC
      LIMIT 100
    `)
    .bind(authentication.user.id)
    .all();

  const rows = result.results || [];
  const items = await getOrderItems(
    env,
    rows.map(order => order.id)
  );

  return json(env, 200, {
    ok: true,
    orders: rows.map(order =>
      serializeOrder(order, items.get(Number(order.id)) || [])
    )
  });
}

async function handleTrackOrder(request, env) {
  const body = await request.json().catch(() => ({}));
  const code = normalizeOrderText(body.code, 40).toUpperCase();
  const phone = normalizePhone(body.phone);

  if (!code || !phone) {
    return json(env, 422, {
      ok: false,
      message: "کد پیگیری و شماره موبایل معتبر وارد کنید."
    });
  }

  const database = requireDatabase(env);
  const order = await database
    .prepare(`
      SELECT
        orders.*,
        users.username
      FROM orders
      LEFT JOIN users
        ON users.id = orders.user_id
      WHERE orders.order_number = ?
        AND (
          orders.customer_phone = ?
          OR orders.receiver_phone = ?
        )
      LIMIT 1
    `)
    .bind(code, phone, phone)
    .first();

  if (!order) {
    return json(env, 404, {
      ok: false,
      message: "سفارشی با این کد و شماره موبایل پیدا نشد."
    });
  }

  const items = await getOrderItems(env, [order.id]);

  return json(env, 200, {
    ok: true,
    order: serializeOrder(
      order,
      items.get(Number(order.id)) || []
    )
  });
}

async function handleAdminOrders(request, env, url) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const search = normalizeOrderText(
    url.searchParams.get("q"),
    80
  );
  const requestedStatus = String(
    url.searchParams.get("status") || "all"
  ).trim().toLowerCase();
  const status =
    requestedStatus === "all"
      ? "all"
      : normalizeOrderStatus(requestedStatus, "all");

  const conditions = [];
  const bindings = [];

  if (search) {
    const pattern = `%${search}%`;
    conditions.push(`(
      orders.order_number LIKE ?
      OR orders.customer_phone LIKE ?
      OR orders.receiver_phone LIKE ?
      OR orders.receiver_name LIKE ?
      OR orders.city LIKE ?
      OR orders.shipping_address LIKE ?
    )`);
    bindings.push(
      pattern,
      pattern,
      pattern,
      pattern,
      pattern,
      pattern
    );
  }

  if (status !== "all") {
    if (status === "new") {
      conditions.push(`orders.status IN ('new', 'pending')`);
    } else {
      conditions.push(`orders.status = ?`);
      bindings.push(status);
    }
  }

  const where = conditions.length
    ? `WHERE ${conditions.join(" AND ")}`
    : "";

  const database = requireDatabase(env);
  const result = await database
    .prepare(`
      SELECT
        orders.*,
        users.username
      FROM orders
      LEFT JOIN users
        ON users.id = orders.user_id
      ${where}
      ORDER BY datetime(orders.created_at) DESC, orders.id DESC
      LIMIT 250
    `)
    .bind(...bindings)
    .all();

  const rows = result.results || [];
  const items = await getOrderItems(
    env,
    rows.map(order => order.id)
  );

  return json(env, 200, {
    ok: true,
    orders: rows.map(order =>
      serializeOrder(order, items.get(Number(order.id)) || [])
    )
  });
}

async function handleAdminOrderStatus(request, env) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const body = await request.json().catch(() => ({}));
  const orderId = normalizePositiveInteger(body.id, Number.MAX_SAFE_INTEGER);
  const nextStatus = normalizeOrderStatus(body.status);
  const nextDatabaseStatus = orderStatusForDatabase(nextStatus);

  if (!orderId || !nextStatus) {
    return json(env, 422, {
      ok: false,
      message: "شناسه یا وضعیت سفارش معتبر نیست."
    });
  }

  const database = requireDatabase(env);
  const order = await database
    .prepare(`
      SELECT *
      FROM orders
      WHERE id = ?
      LIMIT 1
    `)
    .bind(orderId)
    .first();

  if (!order) {
    return json(env, 404, {
      ok: false,
      message: "سفارش پیدا نشد."
    });
  }

  const grouped = await getOrderItems(env, [orderId]);
  const items = grouped.get(orderId) || [];
  const previousStatus = normalizeOrderStatus(order.status, "new");
  const inventoryRestored = Boolean(order.inventory_restored);

  if (
    nextStatus === "cancelled" &&
    previousStatus !== "cancelled" &&
    !inventoryRestored
  ) {
    await restoreInventoryForItems(env, items);

    await database
      .prepare(`
        UPDATE orders
        SET status = 'cancelled',
            inventory_restored = 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(orderId)
      .run();
  } else if (
    previousStatus === "cancelled" &&
    nextStatus !== "cancelled"
  ) {
    const reservation = await reserveInventoryForItems(env, items);

    if (!reservation.ok) {
      return json(env, 409, {
        ok: false,
        message:
          "موجودی کافی برای فعال‌کردن دوباره این سفارش وجود ندارد."
      });
    }

    await database
      .prepare(`
        UPDATE orders
        SET status = ?,
            inventory_restored = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(nextDatabaseStatus, orderId)
      .run();
  } else {
    await database
      .prepare(`
        UPDATE orders
        SET status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(nextDatabaseStatus, orderId)
      .run();
  }

  return json(env, 200, {
    ok: true,
    message: "وضعیت سفارش تغییر کرد.",
    order: await getOrderById(env, orderId)
  });
}

async function handleAdminOrderDelete(request, env) {
  const authentication =
    await requireAdminAuthentication(request, env);

  if (!authentication) {
    return json(env, 403, {
      ok: false,
      message: "دسترسی مدیریت معتبر نیست."
    });
  }

  const body = await request.json().catch(() => ({}));
  const orderId = normalizePositiveInteger(body.id, Number.MAX_SAFE_INTEGER);

  if (!orderId) {
    return json(env, 422, {
      ok: false,
      message: "شناسه سفارش معتبر نیست."
    });
  }

  const database = requireDatabase(env);
  const order = await database
    .prepare(`
      SELECT *
      FROM orders
      WHERE id = ?
      LIMIT 1
    `)
    .bind(orderId)
    .first();

  if (!order) {
    return json(env, 404, {
      ok: false,
      message: "سفارش پیدا نشد."
    });
  }

  const grouped = await getOrderItems(env, [orderId]);
  const items = grouped.get(orderId) || [];

  if (!Boolean(order.inventory_restored)) {
    await restoreInventoryForItems(env, items);
  }

  await database.batch([
    database
      .prepare(`DELETE FROM order_items WHERE order_id = ?`)
      .bind(orderId),
    database
      .prepare(`DELETE FROM orders WHERE id = ?`)
      .bind(orderId)
  ]);

  return json(env, 200, {
    ok: true,
    message: "سفارش حذف شد و موجودی آن بازگردانده شد."
  });
}

function validVisitorId(value) {
  const visitorId = String(value || "").trim();

  return /^[a-zA-Z0-9._:-]{16,100}$/.test(visitorId)
    ? visitorId
    : "";
}

export class PresenceCounter extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);

    this.users = new Map();

    this.ctx.blockConcurrencyWhile(async () => {
      const stored = await this.ctx.storage.get(PRESENCE_STORAGE_KEY);

      if (stored && typeof stored === "object") {
        for (const [id, timestamp] of Object.entries(stored)) {
          const lastSeen = Number(timestamp);

          if (validVisitorId(id) && Number.isFinite(lastSeen)) {
            this.users.set(id, lastSeen);
          }
        }
      }

      this.cleanup(Date.now());
    });
  }

  cleanup(now) {
    for (const [id, lastSeen] of this.users.entries()) {
      if (
        !Number.isFinite(lastSeen) ||
        now - lastSeen > PRESENCE_TTL_MS
      ) {
        this.users.delete(id);
      }
    }
  }

  async persist() {
    if (this.users.size === 0) {
      await this.ctx.storage.delete(PRESENCE_STORAGE_KEY);
      return;
    }

    await this.ctx.storage.put(
      PRESENCE_STORAGE_KEY,
      Object.fromEntries(this.users)
    );
  }

  async scheduleCleanup(now) {
    await this.ctx.storage.setAlarm(
      now + PRESENCE_TTL_MS + 1_000
    );
  }

  async ping(visitorId) {
    const safeId = validVisitorId(visitorId);

    if (!safeId) {
      throw new Error("شناسه کاربر معتبر نیست.");
    }

    const now = Date.now();

    this.cleanup(now);
    this.users.set(safeId, now);

    await this.persist();
    await this.scheduleCleanup(now);

    return {
      online: this.users.size,
      ttl_ms: PRESENCE_TTL_MS
    };
  }

  async alarm() {
    const now = Date.now();

    this.cleanup(now);
    await this.persist();

    if (this.users.size > 0) {
      await this.scheduleCleanup(now);
    }
  }
}

async function handlePresence(request, env) {
  if (!env.PRESENCE) {
    return json(env, 503, {
      ok: false,
      message:
        "اتصال Durable Object با نام PRESENCE تنظیم نشده است."
    });
  }

  const body = await request.json().catch(() => ({}));
  const visitorId = validVisitorId(body.visitor_id);

  if (!visitorId) {
    return json(env, 422, {
      ok: false,
      message: "شناسه کاربر معتبر نیست."
    });
  }

  const stub = env.PRESENCE.getByName("global");
  const result = await stub.ping(visitorId);

  return json(env, 200, {
    ok: true,
    online: result.online,
    approximate: false,
    active_window_seconds: Math.round(result.ttl_ms / 1000)
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const allowed = String(env.ALLOWED_ORIGIN || "").trim();

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: headers(env)
      });
    }

    if (origin && origin !== allowed) {
      return json(env, 403, {
        ok: false,
        message: "آدرس سایت مجاز نیست."
      });
    }

    const url = new URL(request.url);
    const route = routeApiAction(request, url);

    if (route.method === "GET" && route.pathname === "/health") {
      return json(env, 200, {
        ok: true,
        sms_configured: Boolean(
          env.SMS_USERNAME &&
          env.SMS_PASSWORD &&
          env.SMS_DEVICE_ID &&
          env.OTP_SECRET &&
          env.ALLOWED_ORIGIN
        ),
        presence_configured: Boolean(env.PRESENCE),
        database_configured: Boolean(env.datacenter_db),
        sessions_configured: Boolean(env.datacenter_db),
        username_configured: Boolean(env.datacenter_db),
        password_configured: Boolean(env.datacenter_db),
        admin_users_configured: Boolean(env.datacenter_db),
        orders_configured: Boolean(env.datacenter_db),
        profile_configured: Boolean(env.datacenter_db),
        rate_limit_configured: Boolean(env.datacenter_db),
        audit_version: 4,
        session_days: SESSION_TTL_MS / (24 * 60 * 60 * 1000),
        sim: Number(env.SIM_NUMBER || 1)
      });
    }

    try {
      if (
        route.method === "POST" &&
        route.pathname === "/presence/ping"
      ) {
        return await handlePresence(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/request-code"
      ) {
        return await handleRequestCode(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/verify-code"
      ) {
        return await handleVerifyCode(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/register"
      ) {
        return await handleRegister(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/login"
      ) {
        return await handlePasswordLogin(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/reset-password"
      ) {
        return await handleResetPassword(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/admin-login"
      ) {
        return await handleAdminLogin(request, env);
      }

      if (
        route.method === "GET" &&
        route.pathname === "/admin/users"
      ) {
        return await handleAdminUsers(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/admin/users/status"
      ) {
        return await handleAdminUserStatus(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/admin/users/revoke-sessions"
      ) {
        return await handleAdminRevokeSessions(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/admin/users/temporary-password"
      ) {
        return await handleAdminTemporaryPassword(request, env);
      }

      if (
        route.method === "GET" &&
        route.pathname === "/products"
      ) {
        return await handlePublicProducts(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/admin/products/sync"
      ) {
        return await handleAdminProductsSync(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/orders"
      ) {
        return await handleCreateOrder(request, env);
      }

      if (
        route.method === "GET" &&
        route.pathname === "/orders/my"
      ) {
        return await handleMyOrders(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/orders/track"
      ) {
        return await handleTrackOrder(request, env);
      }

      if (
        route.method === "GET" &&
        route.pathname === "/admin/orders"
      ) {
        return await handleAdminOrders(request, env, url);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/admin/orders/status"
      ) {
        return await handleAdminOrderStatus(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/admin/orders/delete"
      ) {
        return await handleAdminOrderDelete(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/change-password"
      ) {
        return await handleChangePassword(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/profile"
      ) {
        return await handleUpdateProfile(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/profile/username"
      ) {
        return await handleSetUsername(request, env);
      }

      if (
        route.method === "GET" &&
        route.pathname === "/me"
      ) {
        return await handleMe(request, env);
      }

      if (
        route.method === "POST" &&
        route.pathname === "/logout"
      ) {
        return await handleLogout(request, env);
      }

      return json(env, 404, {
        ok: false,
        message: "مسیر درخواست پیدا نشد."
      });
    } catch (error) {
      console.error(error);

      return json(env, 502, {
        ok: false,
        message:
          error instanceof Error
            ? error.message
            : "انجام درخواست ممکن نشد."
      });
    }
  }
};

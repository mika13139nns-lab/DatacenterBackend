import fs from 'node:fs';

const workerPath = 'worker.js';
const indexPath = 'index.html';
const blockPath = 'scripts/worker-audit-block.js';

let worker = fs.readFileSync(workerPath, 'utf8');
let index = fs.readFileSync(indexPath, 'utf8');
const auditBlock = fs.readFileSync(blockPath, 'utf8').trim();

function replaceOnce(source, search, replacement, label) {
  if (!source.includes(search)) throw new Error(`Missing anchor: ${label}`);
  const next = source.replace(search, replacement);
  if (next === source) throw new Error(`Replacement failed: ${label}`);
  return next;
}

function replaceRegexOnce(source, regex, replacement, label) {
  if (!regex.test(source)) throw new Error(`Missing regex anchor: ${label}`);
  regex.lastIndex = 0;
  return source.replace(regex, replacement);
}

if (!worker.includes('Audit fixes v5')) {
  worker = replaceOnce(
    worker,
    '\nexport class PresenceCounter extends DurableObject {',
    `\n${auditBlock}\n\nexport class PresenceCounter extends DurableObject {`,
    'insert worker audit block'
  );
}

worker = replaceOnce(
  worker,
  '    updated_at: user.updated_at\n  };',
  '    updated_at: user.updated_at,\n    wallet_balance: Number(user.wallet_balance || 0)\n  };',
  'serialize wallet balance'
);

worker = worker.replaceAll(
  '        users.updated_at,\n        COALESCE(user_profiles.avatar_data, \'\') AS avatar_data,',
  '        users.updated_at,\n        COALESCE(users.wallet_balance, 0) AS wallet_balance,\n        COALESCE(user_profiles.avatar_data, \'\') AS avatar_data,'
);

worker = replaceOnce(
  worker,
  '    presence_ping: { method: "POST", pathname: "/presence/ping" },',
  '    presence_ping: { method: "POST", pathname: "/presence/ping" },\n    reviews: { method: "GET", pathname: "/reviews" },\n    reviews_sync: { method: "POST", pathname: "/reviews/sync" },\n    messages: { method: "GET", pathname: "/messages" },\n    messages_sync: { method: "POST", pathname: "/messages/sync" },',
  'add API aliases'
);

const auditRouteBlock = `
      if (route.method === "POST" && route.pathname === "/verify-code") {
        return await handleVerifyCodeAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/register") {
        return await handleRegisterAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/login") {
        return await handlePasswordLoginAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/admin-login") {
        return await handleAdminLoginAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/reset-password") {
        return await handleResetPasswordAudit(request, env);
      }
      if (route.method === "GET" && route.pathname === "/products") {
        return await handlePublicProductsAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/admin/products/sync") {
        return await handleAdminProductsSyncAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/orders") {
        return await handleCreateOrderAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/admin/orders/status") {
        return await handleAdminOrderStatusAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/admin/orders/delete") {
        return await handleAdminOrderDeleteAudit(request, env);
      }
      if (route.method === "GET" && route.pathname === "/reviews") {
        return await handleReviewsGetAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/reviews/sync") {
        return await handleReviewsSyncAudit(request, env);
      }
      if (route.method === "GET" && route.pathname === "/messages") {
        return await handleMessagesGetAudit(request, env);
      }
      if (route.method === "POST" && route.pathname === "/messages/sync") {
        return await handleMessagesSyncAudit(request, env);
      }
`;

if (!worker.includes('handleVerifyCodeAudit(request, env);')) {
  worker = replaceOnce(
    worker,
    '    try {\n      if (',
    `    try {${auditRouteBlock}\n      if (`,
    'insert audit routes'
  );
}

worker = replaceOnce(
  worker,
  '    approximate: false,',
  '    approximate: true,',
  'presence approximate flag'
);

worker = replaceRegexOnce(
  worker,
  /return json\(env, 502, \{\n\s+ok: false,\n\s+message:\n\s+error instanceof Error\n\s+\? error\.message\n\s+: "انجام درخواست ممکن نشد\."\n\s+\}\);/,
  'return json(env, 500, {\n        ok: false,\n        message: "خطای داخلی سرویس رخ داد؛ دوباره تلاش کنید."\n      });',
  'hide internal errors'
);

index = replaceOnce(
  index,
  '      data:{\n        products:Array.isArray(data.products)\n          ? data.products\n          : []\n      }',
  '      data:{\n        products:Array.isArray(data.products)\n          ? data.products\n          : [],\n        festival:data.festival && typeof data.festival === "object"\n          ? data.festival\n          : {}\n      }',
  'send festival during product sync'
);

index = replaceOnce(
  index,
  '  if(action === "admin_orders"){',
  `  if(action === "reviews"){
    return publicWorkerGet("/reviews");
  }

  if(action === "reviews_sync"){
    const token = getServerSessionToken();
    if(token){
      return serverSessionRequest("/reviews/sync", {method:"POST", data:{reviews:data.reviews || []}});
    }
    return workerRequest("/reviews/sync", {reviews:data.reviews || []});
  }

  if(action === "messages"){
    return serverSessionRequest("/messages", {method:"GET"});
  }

  if(action === "messages_sync"){
    const token = getServerSessionToken();
    if(token){
      return serverSessionRequest("/messages/sync", {method:"POST", data:{messages:data.messages || []}});
    }
    return workerRequest("/messages/sync", {messages:data.messages || []});
  }

  if(action === "admin_orders"){`,
  'frontend review/message actions'
);

index = replaceOnce(
  index,
  '      "/admin/products/sync":"admin_products_sync"',
  '      "/admin/products/sync":"admin_products_sync",\n      "/reviews/sync":"reviews_sync",\n      "/messages":"messages",\n      "/messages/sync":"messages_sync"',
  'session action map additions'
);

index = replaceOnce(
  index,
  '      "/admin-login":"admin_login"',
  '      "/admin-login":"admin_login",\n      "/reviews/sync":"reviews_sync",\n      "/messages/sync":"messages_sync"',
  'public action map additions'
);

index = replaceRegexOnce(
  index,
  /async function loadServerProducts\(\)\{[\s\S]*?\n\}\nasync function syncProductsToServer\(\)\{/,
  `async function loadServerProducts(){
  try{
    const data = await apiRequest("products",{method:"GET"});
    if(Array.isArray(data.products)){
      products = data.products.map(product => normalizeProduct({
        id:Number(product.id),
        name:product.name,
        category:product.category,
        categoryFa:product.categoryFa,
        description:product.description,
        image:product.image,
        price:Number(product.price || 0),
        oldPrice:Number(product.oldPrice || 0),
        stock:Number(product.stock || 0),
        rating:Number(product.rating || 5),
        reviews:Number(product.reviews || 0)
      })).filter(Boolean);
      if(data.festival && typeof data.festival === "object" && Object.keys(data.festival).length){
        festival = normalizeFestival(data.festival);
        safeStorageSet("local","datacenter-festival",JSON.stringify(festival));
      }
      safeStorageSet("local","nova-editable-products",JSON.stringify(products));
      renderProducts(); renderAdminList(); renderFestival(); cleanupCart();
    }
  }catch(e){
    console.warn("Server products:",e.message);
  }
}
async function syncProductsToServer(){`,
  'replace product loading'
);

index = replaceOnce(
  index,
  'if(!isAdmin()||!serverAdminCsrf)return;\n  try{await apiRequest("admin_products_sync",{csrf:"admin",data:{products:products.map(p=>({id:p.id,name:p.name,category:p.category,categoryFa:p.categoryFa,description:p.description,image:p.image,price:p.price,sale_price:festivalProductPrice(p),oldPrice:p.oldPrice,discount:festivalDiscountForProduct(p),stock:p.stock}))}});',
  'if(!isAdmin()||!serverAdminCsrf)return;\n  try{await apiRequest("admin_products_sync",{csrf:"admin",data:{products:products.map(p=>({id:p.id,name:p.name,category:p.category,categoryFa:p.categoryFa,description:p.description,image:p.image,price:p.price,oldPrice:p.oldPrice,discount:festivalDiscountForProduct(p),stock:p.stock,rating:p.rating,reviews:p.reviews})),festival}});',
  'full product sync payload'
);

index = replaceOnce(
  index,
  '  renderFestival();\n}\n\n\nfunction saveMessages(){',
  '  renderFestival();\n  syncReviewsToServer();\n}\n\nasync function syncReviewsToServer(){\n  try{\n    const data = await apiRequest("reviews_sync",{data:{reviews}});\n    if(Array.isArray(data.reviews)){ reviews=data.reviews.map(normalizeReview).filter(Boolean); safeStorageSet("local","datacenter-reviews",JSON.stringify(reviews)); renderReviews(); renderAdminReviews(); }\n  }catch(error){ console.warn("Review sync:",error.message); }\n}\n\nasync function loadServerReviews(admin=false){\n  try{\n    const data = admin && getServerSessionToken() ? await serverSessionRequest("/reviews",{method:"GET"}) : await apiRequest("reviews",{method:"GET"});\n    if(Array.isArray(data.reviews)){ reviews=data.reviews.map(normalizeReview).filter(Boolean); safeStorageSet("local","datacenter-reviews",JSON.stringify(reviews)); renderReviews(); renderAdminReviews(); }\n  }catch(error){ console.warn("Review load:",error.message); }\n}\n\nfunction saveMessages(){',
  'review server sync functions'
);

index = replaceOnce(
  index,
  '  renderAdminMessages();\n}\n\nfunction saveCart(){',
  '  renderAdminMessages();\n  syncMessagesToServer();\n}\n\nasync function syncMessagesToServer(){\n  try{ await apiRequest("messages_sync",{data:{messages}}); }catch(error){ console.warn("Message sync:",error.message); }\n}\n\nasync function loadServerMessages(){\n  if(!getServerSessionToken()) return;\n  try{ const data=await apiRequest("messages",{method:"GET"}); if(Array.isArray(data.messages)){ messages=data.messages.map(normalizeMessage).filter(Boolean); safeStorageSet("local","datacenter-contact-messages",JSON.stringify(messages)); renderAdminMessages(); } }catch(error){ console.warn("Message load:",error.message); }\n}\n\nfunction saveCart(){',
  'message server sync functions'
);

index = replaceOnce(
  index,
  '  }else if(safeSection === "reviews"){\n    renderAdminReviews();',
  '  }else if(safeSection === "reviews"){\n    renderAdminReviews();\n    loadServerReviews(true);',
  'admin reviews load'
);
index = replaceOnce(
  index,
  '  }else if(safeSection === "contact"){\n    renderAdminMessages();',
  '  }else if(safeSection === "contact"){\n    renderAdminMessages();\n    loadServerMessages();',
  'admin messages load'
);

index = replaceOnce(
  index,
  'window.setTimeout(async()=>{await accountBootstrap();await loadServerProducts();},0);',
  'window.setTimeout(async()=>{await accountBootstrap();await loadServerProducts();await loadServerReviews(false);},0);',
  'bootstrap reviews'
);

index = replaceOnce(
  index,
  '  const items=currentCartOrderItems();if(!items.length){showToast("سبد خرید خالی است.");return;}\n  try{\n    const data=await apiRequest("create_order",{csrf:"user",data:{customer_name:',
  '  const items=currentCartOrderItems();if(!items.length){showToast("سبد خرید خالی است.");return;}\n  const form=event.currentTarget;if(form.dataset.busy==="1")return;form.dataset.busy="1";const submit=event.submitter||form.querySelector(\'button[type="submit"]\');if(submit)submit.disabled=true;\n  const requestId=crypto.randomUUID?.()||`${Date.now()}-${Math.random().toString(36).slice(2)}`;\n  try{\n    const data=await apiRequest("create_order",{csrf:"user",data:{request_id:requestId,customer_name:',
  'order busy and idempotency'
);
index = replaceOnce(
  index,
  '  }catch(e){showToast(e.message);}\n}, true);',
  '  }catch(e){showToast(e.message);}finally{form.dataset.busy="0";if(submit)submit.disabled=false;}\n}, true);',
  'order finally unlock'
);

index = replaceOnce(
  index,
  '  const phone=$("#checkoutPhone");phone.value=currentUser.phone;phone.readOnly=true;phone.removeAttribute("data-no-autofill");',
  '  const phone=$("#checkoutPhone");phone.value=currentUser.phone;phone.readOnly=true;phone.removeAttribute("data-no-autofill");\n  const applyDeliveryMode=()=>{const pickup=$("#checkoutDelivery").value==="pickup";["checkoutProvince","checkoutCity","checkoutPostalCode","checkoutAddress"].forEach(id=>{const field=$("#"+id);if(!field)return;field.required=!pickup;field.disabled=pickup;if(pickup)clearCheckoutFieldError(id);});};applyDeliveryMode();$("#checkoutDelivery").onchange=applyDeliveryMode;',
  'pickup client fields'
);

index = replaceOnce(
  index,
  '  badgeNode.title = "تعداد واقعی کاربران فعال در لحظه";',
  '    badgeNode.title = "تعداد تقریبی دستگاه‌های فعال در ۴۵ ثانیه اخیر";',
  'online wording'
);

fs.writeFileSync(workerPath, worker);
fs.writeFileSync(indexPath, index);
console.log('Audit fixes applied successfully.');

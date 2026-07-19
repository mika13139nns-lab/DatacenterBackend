# فروشگاه دیتاسنتر — GitHub Pages + Cloudflare Worker

این پروژه از Render یا Python استفاده نمی‌کند. فرانت‌اند با `index.html` از GitHub Pages سرو می‌شود و بک‌اند، یک Cloudflare Worker با فایل ورودی `worker.js` است.

## معماری

- **Frontend:** فایل `index.html` روی GitHub Pages
- **Backend:** Cloudflare Worker در `worker.js`
- **Config:** تنظیمات Worker در `wrangler.jsonc`
- **Database:** Cloudflare D1 از طریق binding با نام `datacenter_db`
- **Presence:** Durable Object از طریق binding با نام `PRESENCE`
- **SMS:** از SMS gateway تنظیم‌شده در secrets/vars محیط Worker استفاده می‌شود

## اجرای محلی

```bash
npx wrangler dev
```

## استقرار تولید

```bash
npx wrangler deploy
```

## تنظیمات محرمانه

هیچ رمز، API key، توکن، اطلاعات SMS، اطلاعات مدیر یا merchant ID را داخل فایل‌های commit‌شده قرار ندهید. مقادیر محرمانه باید با Cloudflare Worker secrets یا فایل محلی `.dev.vars` تنظیم شوند.

نمونه موارد لازم برای محیط Worker:

- `SMS_USERNAME`
- `SMS_PASSWORD`
- `SMS_DEVICE_ID`
- `OTP_SECRET`
- `SESSION_SECRET` در صورت استفاده از قابلیت مرتبط

## بررسی سلامت Worker

پس از اجرای Worker، مسیر زیر باید JSON موفق برگرداند:

```text
https://YOUR-WORKER-DOMAIN/health
```

## نکات مهم توسعه

- فایل‌های قدیمی Python/Render مانند `app.py`، `render.yaml` و `requirements.txt` نباید به مخزن برگردند.
- مسیرهای API باید با مسیرهای پیاده‌سازی‌شده در `worker.js` هماهنگ باشند.
- bindingهای `datacenter_db` و `PRESENCE` در `wrangler.jsonc` باید حفظ شوند.
- فرانت‌اند برای API از Worker استفاده می‌کند و روی GitHub Pages به بک‌اند Python یا Render وابسته نیست.

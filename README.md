# فروشگاه دیتاسنتر — GitHub + Render

این نسخه برای اجرای عمومی سایت روی Render آماده شده است. GitHub کد را نگه می‌دارد و Render سایت و سرور Python را اجرا می‌کند.

## امکانات تستی

- ثبت‌نام با کد پیامکی واقعی از SMS Gate Cloud
- ورود کاربر
- انتخاب SIM 1 یا SIM 2 از Environment Variables
- پنل مدیریت
- سفارش و پیگیری سفارش
- بدون دیتابیس دائمی

> این نسخه برای تست است. کاربران و سفارش‌ها در RAM نگه داشته می‌شوند و با Restart یا Deploy مجدد Render پاک می‌شوند.

## آپلود در GitHub

1. یک Repository جدید بسازید.
2. تمام فایل‌های همین پوشه را در ریشه Repository آپلود کنید.
3. فایل `.env.example` فقط نمونه است و رمز واقعی داخل آن قرار ندهید.
4. Username، Password و Device ID واقعی را هرگز داخل GitHub ثبت نکنید.

## ساخت روی Render

1. در Render گزینه `New +` و سپس `Blueprint` را انتخاب کنید.
2. Repository گیت‌هاب را متصل کنید.
3. Render فایل `render.yaml` را شناسایی می‌کند.
4. مقدار Environment Variableهای محرمانه را وارد کنید:

- `SMS_GATE_USERNAME`: نام کاربری Cloud
- `SMS_GATE_PASSWORD`: رمز Cloud
- `SMS_GATE_DEVICE_ID`: شناسه دستگاه Cloud
- `SMS_GATE_SIM_NUMBER`: عدد `1` یا `2`
- `ADMIN_PASSWORD`: رمز مدیریت سایت

5. Deploy را اجرا کنید.
6. پس از آماده‌شدن، Render یک آدرس عمومی HTTPS می‌دهد.

## تغییر سیم‌کارت

در Render وارد Service شوید:

`Environment → SMS_GATE_SIM_NUMBER`

- `1` برای سیم‌کارت اول
- `2` برای سیم‌کارت دوم

بعد `Save Changes` را بزنید تا سرویس دوباره Deploy شود.

## بررسی سلامت سرور

آدرس زیر باید JSON موفق برگرداند:

`https://YOUR-RENDER-DOMAIN/health`

## نکات ضروری

- Cloud Server برنامه SMS Gate باید روشن و آنلاین باشد.
- گوشی فرستنده باید اینترنت داشته باشد.
- برای تشخیص سیم‌ها، مجوز Phone برنامه فعال باشد.
- GitHub Pages برای این پروژه لازم نیست، چون خود Render فایل `index.html` و API را با یک دامنه سرو می‌کند.

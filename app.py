# -*- coding: utf-8 -*-
"""
سرور آزمایشی فروشگاه دیتاسنتر، بدون دیتابیس

- سایت کامل index.html را اجرا می‌کند.
- ثبت‌نام سه مرحله‌ای و ورود را آزمایش می‌کند.
- کد ۶ رقمی را با SMS Gateway for Android از سیم‌کارت می‌فرستد.
- کاربران، نشست‌ها و سفارش‌ها فقط در RAM هستند.
- با بستن برنامه همه اطلاعات پاک می‌شوند.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10000"))
DEFAULT_GATEWAY_URL = "http://192.168.1.4:8080/message"

OTP_DIGITS = 6
OTP_EXPIRE_SECONDS = 5 * 60
OTP_RESEND_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_DAILY_LIMIT = 10
VERIFICATION_TOKEN_SECONDS = 15 * 60
REMEMBER_SECONDS = 30 * 24 * 60 * 60
NORMAL_SESSION_SECONDS = 24 * 60 * 60
ADMIN_USERNAME = "ADMIN"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "DC@Qazvin#60_1405")

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "index.html"

GATEWAY_MODE = os.environ.get("SMS_GATE_MODE", "cloud").strip().lower()
GATEWAY_URL = os.environ.get(
    "SMS_GATE_URL",
    "https://api.sms-gate.app/3rdparty/v1/messages",
).strip()
GATEWAY_USERNAME = os.environ.get("SMS_GATE_USERNAME", "").strip()
GATEWAY_PASSWORD = os.environ.get("SMS_GATE_PASSWORD", "").strip()
GATEWAY_DEVICE_ID = os.environ.get("SMS_GATE_DEVICE_ID", "").strip()

try:
    SELECTED_SIM_NUMBER = int(os.environ.get("SMS_GATE_SIM_NUMBER", "1"))
except ValueError:
    SELECTED_SIM_NUMBER = 1

if SELECTED_SIM_NUMBER not in (1, 2):
    SELECTED_SIM_NUMBER = 1

LOCK = threading.RLock()
USERS: dict[int, dict[str, Any]] = {}
USER_BY_PHONE: dict[str, int] = {}
USER_BY_USERNAME: dict[str, int] = {}
SESSIONS: dict[str, dict[str, Any]] = {}
ADMIN_SESSIONS: dict[str, dict[str, Any]] = {}
OTPS: dict[tuple[str, str], dict[str, Any]] = {}
OTP_REQUEST_LOG: dict[str, list[float]] = {}
VERIFICATION_FLOWS: dict[str, dict[str, Any]] = {}
ORDERS: list[dict[str, Any]] = []
NEXT_USER_ID = 1
NEXT_ORDER_ID = 1


def now() -> float:
    return time.time()


def now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def normalize_digits(value: Any) -> str:
    table = str.maketrans(
        "۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩",
        "01234567890123456789",
    )
    return str(value or "").translate(table)


def digits_only(value: Any) -> str:
    return re.sub(r"\D+", "", normalize_digits(value))


def normalize_phone(value: Any) -> str:
    number = digits_only(value)

    if number.startswith("0098"):
        number = "0" + number[4:]
    elif number.startswith("98") and len(number) == 12:
        number = "0" + number[2:]

    return number


def valid_phone(phone: str) -> bool:
    return re.fullmatch(r"09\d{9}", phone) is not None


def phone_to_e164(phone: str) -> str:
    if not valid_phone(phone):
        raise ValueError("شماره موبایل معتبر نیست.")
    return "+98" + phone[1:]


def valid_username(username: str) -> bool:
    return re.fullmatch(r"[a-z][a-z0-9_]{3,23}", username) is not None


def valid_password(password: str) -> bool:
    return bool(
        8 <= len(password) <= 64
        and re.search(r"[a-z]", password)
        and re.search(r"[A-Z]", password)
        and re.search(r"\d", password)
        and re.search(r"[^A-Za-z0-9]", password)
        and not re.search(r"\s", password)
    )


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    real_salt = salt or secrets.token_bytes(16)
    result = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        real_salt,
        180_000,
    )
    return real_salt.hex(), result.hex()


def verify_password(password: str, salt_hex: str, expected_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False

    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, expected_hex)


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(user["id"]),
        "phone": str(user["phone"]),
        "username": str(user["username"]),
        "wallet_balance": int(user.get("wallet_balance", 0)),
        "created_at": str(user.get("created_at", "")),
    }


def create_code() -> str:
    minimum = 10 ** (OTP_DIGITS - 1)
    maximum = (10 ** OTP_DIGITS) - 1
    return str(secrets.randbelow(maximum - minimum + 1) + minimum)


def otp_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def send_sms(phone: str, code: str, purpose: str) -> None:
    title = (
        "کد بازیابی گذرواژه"
        if purpose == "reset"
        else "کد تأیید ثبت‌نام"
    )
    message = (
        f"{title} فروشگاه دیتاسنتر: {code}\n"
        "این کد را در اختیار دیگران قرار ندهید."
    )

    payload = {
        "phoneNumbers": [phone_to_e164(phone)],
        "textMessage": {"text": message},
        "simNumber": SELECTED_SIM_NUMBER,
        "ttl": 300,
        "priority": 100,
    }

    if GATEWAY_MODE == "cloud" and GATEWAY_DEVICE_ID:
        payload["deviceId"] = GATEWAY_DEVICE_ID

    credentials = f"{GATEWAY_USERNAME}:{GATEWAY_PASSWORD}".encode("utf-8")
    authorization = base64.b64encode(credentials).decode("ascii")

    request = urllib.request.Request(
        GATEWAY_URL,
        data=json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            if not 200 <= response.status < 300:
                raise RuntimeError(
                    f"گوشی فرستنده درخواست را نپذیرفت؛ HTTP {response.status}"
                )

            if body:
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    data = {}

                state = str(data.get("state", "")).lower()
                if state == "failed":
                    raise RuntimeError(
                        "برنامه SMS Gateway پیام را ناموفق اعلام کرد."
                    )

    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")

        if error.code in (401, 403):
            raise RuntimeError(
                "نام کاربری یا رمز برنامه SMS Gateway اشتباه است."
            ) from error

        if error.code == 404:
            raise RuntimeError(
                "مسیر پیامک پیدا نشد؛ آدرس باید به /message ختم شود."
            ) from error

        raise RuntimeError(
            f"خطای SMS Gateway: HTTP {error.code} {body[:200]}"
        ) from error

    except urllib.error.URLError as error:
        if GATEWAY_MODE == "cloud":
            raise RuntimeError(
                "اتصال به Cloud Server انجام نشد؛ اینترنت و اطلاعات Cloud را بررسی کنید."
            ) from error
        raise RuntimeError(
            "اتصال به گوشی فرستنده انجام نشد؛ وای‌فای، IP و ONLINE بودن Local Server را بررسی کنید."
        ) from error


def cleanup() -> None:
    current = now()

    for sid in list(SESSIONS):
        if float(SESSIONS[sid].get("expires_at", 0)) <= current:
            SESSIONS.pop(sid, None)

    for sid in list(ADMIN_SESSIONS):
        if float(ADMIN_SESSIONS[sid].get("expires_at", 0)) <= current:
            ADMIN_SESSIONS.pop(sid, None)

    for key in list(OTPS):
        record = OTPS[key]
        if float(record.get("expires_at", 0)) + 600 <= current:
            OTPS.pop(key, None)

    for token in list(VERIFICATION_FLOWS):
        flow = VERIFICATION_FLOWS[token]
        if float(flow.get("expires_at", 0)) <= current or flow.get("used"):
            VERIFICATION_FLOWS.pop(token, None)

    one_day_ago = current - 86400
    for phone, timestamps in list(OTP_REQUEST_LOG.items()):
        filtered = [stamp for stamp in timestamps if stamp >= one_day_ago]
        if filtered:
            OTP_REQUEST_LOG[phone] = filtered
        else:
            OTP_REQUEST_LOG.pop(phone, None)


def make_tracking_code() -> str:
    stamp = int(now())
    return f"DC-{stamp:X}-{secrets.token_hex(2).upper()}"


def get_local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


@dataclass
class ApiError(Exception):
    message: str
    status: int = 422
    code: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class Handler(BaseHTTPRequestHandler):
    server_version = "DatacenterNoDb/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[WEB] {self.address_string()} - {fmt % args}")

    def cookie_sid(self, name: str) -> str | None:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()

        try:
            jar.load(raw)
        except cookies.CookieError:
            return None

        morsel = jar.get(name)
        if morsel is None:
            return None

        value = morsel.value
        if re.fullmatch(r"[A-Za-z0-9_-]{20,150}", value):
            return value
        return None

    def user_session(self) -> tuple[str | None, dict[str, Any] | None]:
        sid = self.cookie_sid("dc_user_session")
        if not sid:
            return None, None

        session = SESSIONS.get(sid)
        if not session or float(session.get("expires_at", 0)) <= now():
            SESSIONS.pop(sid, None)
            return None, None

        return sid, session

    def admin_session(self) -> tuple[str | None, dict[str, Any] | None]:
        sid = self.cookie_sid("dc_admin_session")
        if not sid:
            return None, None

        session = ADMIN_SESSIONS.get(sid)
        if not session or float(session.get("expires_at", 0)) <= now():
            ADMIN_SESSIONS.pop(sid, None)
            return None, None

        return sid, session

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ApiError("طول درخواست معتبر نیست.", 400) from error

        if length < 0 or length > 100_000:
            raise ApiError("حجم درخواست معتبر نیست.", 413)

        if length == 0:
            return {}

        raw = self.rfile.read(length)

        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ApiError("ساختار درخواست معتبر نیست.", 400) from error

        if not isinstance(result, dict):
            raise ApiError("ساختار درخواست معتبر نیست.", 400)

        return result

    def send_json(
        self,
        status: int,
        data: dict[str, Any],
        set_cookies: list[str] | None = None,
    ) -> None:
        body = json.dumps(
            data,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")

        for value in set_cookies or []:
            self.send_header("Set-Cookie", value)

        self.end_headers()
        self.wfile.write(body)

    def ok(
        self,
        data: dict[str, Any] | None = None,
        status: int = 200,
        set_cookies: list[str] | None = None,
    ) -> None:
        self.send_json(
            status,
            {"ok": True, **(data or {})},
            set_cookies,
        )

    def fail(self, error: ApiError) -> None:
        self.send_json(
            error.status,
            {
                "ok": False,
                "message": error.message,
                "code": error.code,
                **error.extra,
            },
        )

    def require_csrf(
        self,
        session: dict[str, Any] | None,
        kind: str,
    ) -> None:
        if not session:
            raise ApiError(
                "نشست شما تمام شده است؛ دوباره وارد شوید.",
                401,
            )

        supplied = self.headers.get("X-CSRF-Token", "")
        expected = str(session.get("csrf", ""))

        if not supplied or not hmac.compare_digest(supplied, expected):
            raise ApiError(f"توکن امنیتی {kind} معتبر نیست.", 403)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path in ("/", "/index.html"):
            if not INDEX_FILE.exists():
                self.send_error(500, "index.html پیدا نشد")
                return

            body = INDEX_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if parsed.path == "/health":
            body = json.dumps(
                {
                    "ok": True,
                    "service": "datacenter-shop",
                    "sms_mode": GATEWAY_MODE,
                    "sms_configured": bool(
                        GATEWAY_USERNAME
                        and GATEWAY_PASSWORD
                        and (
                            GATEWAY_MODE != "cloud"
                            or GATEWAY_DEVICE_ID
                        )
                    ),
                },
                ensure_ascii=False,
            ).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/api":
            self.handle_api("GET", parsed)
            return

        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api":
            self.handle_api("POST", parsed)
            return

        self.send_error(404)

    def handle_api(
        self,
        method: str,
        parsed: urllib.parse.ParseResult,
    ) -> None:
        try:
            with LOCK:
                cleanup()

            query = urllib.parse.parse_qs(parsed.query)
            action = str(query.get("action", [""])[0])
            data = self.read_json() if method == "POST" else {}
            result = self.dispatch(action, method, query, data)

            if result is not None:
                payload, status, cookie_headers = result
                self.ok(payload, status, cookie_headers)

        except ApiError as error:
            self.fail(error)
        except RuntimeError as error:
            self.fail(ApiError(str(error), 502))
        except Exception as error:
            print(f"[ERROR] {type(error).__name__}: {error}")
            self.fail(ApiError("خطای داخلی سرور رخ داد.", 500))

    def dispatch(
        self,
        action: str,
        method: str,
        query: dict[str, list[str]],
        data: dict[str, Any],
    ) -> tuple[dict[str, Any], int, list[str]] | None:
        global NEXT_USER_ID, NEXT_ORDER_ID

        if action == "health":
            return {
                "message": "سرور آزمایشی بدون دیتابیس آماده است.",
                "database": False,
                "sms": "local_gateway",
            }, 200, []

        if action == "request_code":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            phone = normalize_phone(data.get("phone"))
            purpose = str(data.get("purpose", "register"))

            if not valid_phone(phone):
                raise ApiError(
                    "شماره موبایل باید دقیقاً ۱۱ رقم و با 09 شروع شود."
                )

            if purpose not in ("register", "reset"):
                raise ApiError("نوع درخواست کد معتبر نیست.")

            exists = phone in USER_BY_PHONE

            if purpose == "register" and exists:
                raise ApiError(
                    "این شماره قبلاً ثبت‌نام کرده است؛ وارد حساب شوید.",
                    409,
                )

            if purpose == "reset" and not exists:
                raise ApiError(
                    "حسابی با این شماره پیدا نشد.",
                    404,
                )

            with LOCK:
                timestamps = OTP_REQUEST_LOG.setdefault(phone, [])
                one_day_ago = now() - 86400
                timestamps[:] = [
                    stamp for stamp in timestamps
                    if stamp >= one_day_ago
                ]

                if len(timestamps) >= OTP_DAILY_LIMIT:
                    raise ApiError(
                        "تعداد درخواست‌های امروز بیش از حد مجاز است.",
                        429,
                    )

                old = OTPS.get((phone, purpose))
                if old:
                    remaining = int(
                        OTP_RESEND_SECONDS
                        - (now() - float(old.get("sent_at", 0)))
                    )
                    if remaining > 0:
                        raise ApiError(
                            f"برای ارسال مجدد {remaining} ثانیه صبر کنید.",
                            429,
                        )

            code = create_code()
            send_sms(phone, code, purpose)

            with LOCK:
                OTPS[(phone, purpose)] = {
                    "hash": otp_hash(code),
                    "expires_at": now() + OTP_EXPIRE_SECONDS,
                    "attempts": 0,
                    "sent_at": now(),
                }
                OTP_REQUEST_LOG.setdefault(phone, []).append(now())

            return {
                "message": "کد تأیید ۶ رقمی پیامک شد.",
                "retry_after": OTP_RESEND_SECONDS,
            }, 200, []

        if action == "verify_code":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            phone = normalize_phone(data.get("phone"))
            purpose = str(data.get("purpose", ""))
            code = digits_only(data.get("code"))

            if not valid_phone(phone):
                raise ApiError("شماره موبایل معتبر نیست.")

            if purpose not in ("register", "reset"):
                raise ApiError("نوع تأیید معتبر نیست.")

            if re.fullmatch(r"\d{6}", code) is None:
                raise ApiError("کد تأیید باید دقیقاً ۶ رقم باشد.")

            with LOCK:
                record = OTPS.get((phone, purpose))

                if not record:
                    raise ApiError(
                        "ابتدا درخواست ارسال کد بدهید.",
                        404,
                    )

                if float(record["expires_at"]) <= now():
                    OTPS.pop((phone, purpose), None)
                    raise ApiError(
                        "کد منقضی شده است؛ دوباره کد بگیرید.",
                        410,
                    )

                if int(record["attempts"]) >= OTP_MAX_ATTEMPTS:
                    raise ApiError(
                        "تعداد تلاش بیش از حد مجاز است؛ کد جدید بگیرید.",
                        429,
                    )

                if not hmac.compare_digest(
                    otp_hash(code),
                    str(record["hash"]),
                ):
                    record["attempts"] = int(record["attempts"]) + 1
                    raise ApiError("کد تأیید اشتباه است.")

                OTPS.pop((phone, purpose), None)
                token = secrets.token_urlsafe(48)
                VERIFICATION_FLOWS[token] = {
                    "phone": phone,
                    "purpose": purpose,
                    "expires_at": now() + VERIFICATION_TOKEN_SECONDS,
                    "used": False,
                }

            return {
                "message": "شماره موبایل تأیید شد.",
                "verification_token": token,
                "expires_in": VERIFICATION_TOKEN_SECONDS,
            }, 200, []

        if action == "register":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            phone = normalize_phone(data.get("phone"))
            token = str(data.get("verification_token", ""))
            username = str(data.get("username", "")).strip().lower()
            password = str(data.get("password", ""))
            confirm = str(data.get("password_confirm", ""))

            if not valid_phone(phone):
                raise ApiError("شماره موبایل معتبر نیست.")

            if not valid_username(username):
                raise ApiError(
                    "نام کاربری باید ۴ تا ۲۴ کاراکتر و فقط شامل "
                    "حروف انگلیسی، عدد و زیرخط باشد."
                )

            if password != confirm:
                raise ApiError("تکرار رمز عبور یکسان نیست.")

            if not valid_password(password):
                raise ApiError(
                    "رمز باید ۸ تا ۶۴ کاراکتر و شامل حرف کوچک، "
                    "حرف بزرگ، عدد و نماد باشد."
                )

            with LOCK:
                flow = VERIFICATION_FLOWS.get(token)

                if (
                    not flow
                    or flow.get("used")
                    or flow.get("purpose") != "register"
                    or flow.get("phone") != phone
                    or float(flow.get("expires_at", 0)) <= now()
                ):
                    raise ApiError(
                        "تأیید شماره منقضی یا استفاده‌شده است؛ "
                        "دوباره کد بگیرید.",
                        401,
                    )

                if phone in USER_BY_PHONE:
                    raise ApiError(
                        "این شماره قبلاً ثبت‌نام کرده است.",
                        409,
                    )

                if username in USER_BY_USERNAME:
                    raise ApiError(
                        "این نام کاربری قبلاً انتخاب شده است.",
                        409,
                    )

                user_id = NEXT_USER_ID
                NEXT_USER_ID += 1
                salt, password_hash = hash_password(password)
                user = {
                    "id": user_id,
                    "phone": phone,
                    "username": username,
                    "password_salt": salt,
                    "password_hash": password_hash,
                    "wallet_balance": 0,
                    "created_at": now_text(),
                    "last_login_at": "",
                }

                USERS[user_id] = user
                USER_BY_PHONE[phone] = user_id
                USER_BY_USERNAME[username] = user_id
                flow["used"] = True

                sid = secrets.token_urlsafe(48)
                csrf = secrets.token_urlsafe(32)
                SESSIONS[sid] = {
                    "user_id": user_id,
                    "csrf": csrf,
                    "expires_at": now() + REMEMBER_SECONDS,
                }

            cookie = (
                f"dc_user_session={sid}; Path=/; HttpOnly; "
                f"SameSite=Lax; Max-Age={REMEMBER_SECONDS}"
            )

            return {
                "message": (
                    "ثبت‌نام انجام شد و وارد حساب شدید."
                ),
                "user": public_user(user),
                "csrf": csrf,
            }, 201, [cookie]

        if action == "login":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            identity_raw = str(data.get("identity", "")).strip()
            identity = identity_raw.lower()
            password = str(data.get("password", ""))
            remember = data.get("remember", True) is not False
            phone_identity = normalize_phone(identity_raw)

            with LOCK:
                user_id = None

                if valid_phone(phone_identity):
                    user_id = USER_BY_PHONE.get(phone_identity)

                if user_id is None:
                    user_id = USER_BY_USERNAME.get(identity)

                user = USERS.get(int(user_id)) if user_id else None

                if not user or not verify_password(
                    password,
                    str(user["password_salt"]),
                    str(user["password_hash"]),
                ):
                    raise ApiError(
                        "نام کاربری/شماره یا رمز عبور نادرست است.",
                        401,
                    )

                sid = secrets.token_urlsafe(48)
                csrf = secrets.token_urlsafe(32)
                lifetime = (
                    REMEMBER_SECONDS
                    if remember
                    else NORMAL_SESSION_SECONDS
                )

                SESSIONS[sid] = {
                    "user_id": int(user["id"]),
                    "csrf": csrf,
                    "expires_at": now() + lifetime,
                }
                user["last_login_at"] = now_text()

            cookie = (
                f"dc_user_session={sid}; Path=/; HttpOnly; "
                f"SameSite=Lax; Max-Age={lifetime}"
            )

            return {
                "message": "با موفقیت وارد شدید.",
                "user": public_user(user),
                "csrf": csrf,
            }, 200, [cookie]

        if action == "me":
            if method != "GET":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            _, session = self.user_session()

            if not session:
                return {
                    "authenticated": False,
                    "csrf": "",
                    "orders": [],
                }, 200, []

            with LOCK:
                user = USERS.get(int(session["user_id"]))

                if not user:
                    return {
                        "authenticated": False,
                        "csrf": "",
                        "orders": [],
                    }, 200, []

                user_orders = [
                    order.copy()
                    for order in ORDERS
                    if int(order["user_id"]) == int(user["id"])
                ]

            return {
                "authenticated": True,
                "user": public_user(user),
                "orders": user_orders,
                "csrf": str(session["csrf"]),
            }, 200, []

        if action == "logout":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            sid, session = self.user_session()

            if session:
                self.require_csrf(session, "کاربر")

            if sid:
                with LOCK:
                    SESSIONS.pop(sid, None)

            expired = (
                "dc_user_session=; Path=/; HttpOnly; "
                "SameSite=Lax; Max-Age=0"
            )
            return {"message": "از حساب خارج شدید."}, 200, [expired]

        if action == "reset_password":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            phone = normalize_phone(data.get("phone"))
            token = str(data.get("verification_token", ""))
            password = str(data.get("password", ""))
            confirm = str(data.get("password_confirm", ""))

            if not valid_phone(phone):
                raise ApiError("شماره موبایل معتبر نیست.")

            if password != confirm:
                raise ApiError("تکرار رمز جدید یکسان نیست.")

            if not valid_password(password):
                raise ApiError("رمز جدید همه شرایط امنیتی را ندارد.")

            with LOCK:
                flow = VERIFICATION_FLOWS.get(token)

                if (
                    not flow
                    or flow.get("used")
                    or flow.get("purpose") != "reset"
                    or flow.get("phone") != phone
                    or float(flow.get("expires_at", 0)) <= now()
                ):
                    raise ApiError(
                        "کد بازیابی منقضی یا استفاده‌شده است.",
                        401,
                    )

                user_id = USER_BY_PHONE.get(phone)
                user = USERS.get(int(user_id)) if user_id else None

                if not user:
                    raise ApiError("حساب کاربری پیدا نشد.", 404)

                # رمز قبلی فقط بعد از تکمیل تمام اعتبارسنجی‌ها عوض می‌شود.
                salt, password_hash = hash_password(password)
                user["password_salt"] = salt
                user["password_hash"] = password_hash
                flow["used"] = True

                for sid in list(SESSIONS):
                    if int(SESSIONS[sid]["user_id"]) == int(user["id"]):
                        SESSIONS.pop(sid, None)

            return {
                "message": (
                    "رمز جدید ثبت شد؛ حالا با نام کاربری و رمز جدید "
                    "وارد شوید."
                )
            }, 200, []

        if action == "products":
            if method != "GET":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            # فهرست محصولات داخل خود HTML قرار دارد.
            return {"products": []}, 200, []

        if action == "create_order":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            _, session = self.user_session()
            self.require_csrf(session, "کاربر")

            if session is None:
                raise ApiError("ابتدا وارد حساب شوید.", 401)

            with LOCK:
                user = USERS.get(int(session["user_id"]))

            if not user:
                raise ApiError("حساب کاربری پیدا نشد.", 401)

            customer_name = str(
                data.get("customer_name", "")
            ).strip()[:70]
            province = str(data.get("province", "")).strip()[:40]
            city = str(data.get("city", "")).strip()[:40]
            postal_code = digits_only(data.get("postal_code"))[:20]
            address = str(data.get("address", "")).strip()[:500]
            delivery = (
                "pickup"
                if data.get("delivery") == "pickup"
                else "shipping"
            )
            note = str(data.get("note", "")).strip()[:500]
            raw_items = data.get("items", [])

            if len(customer_name) < 2:
                raise ApiError("نام و نام خانوادگی را کامل وارد کنید.")

            if len(province) < 2 or len(city) < 2:
                raise ApiError("استان و شهر معتبر نیست.")

            if re.fullmatch(r"\d{5,20}", postal_code) is None:
                raise ApiError("کد پستی معتبر نیست.")

            if len(address) < 5:
                raise ApiError("آدرس کامل را وارد کنید.")

            if len(note) < 2:
                raise ApiError("توضیحات سفارش را وارد کنید.")

            if not isinstance(raw_items, list) or not raw_items:
                raise ApiError("سبد خرید معتبر نیست.")

            items: list[dict[str, Any]] = []
            total = 0

            for raw in raw_items[:100]:
                if not isinstance(raw, dict):
                    raise ApiError("یکی از اقلام سفارش معتبر نیست.")

                product_id = int(raw.get("product_id", 0))
                name = str(raw.get("name", "")).strip()[:120]
                quantity = int(raw.get("quantity", 0))
                unit_price = int(raw.get("unit_price", 0))
                original_price = int(raw.get("original_price", unit_price))
                discount = int(raw.get("discount", 0))
                line_total = int(raw.get("line_total", 0))

                if (
                    product_id <= 0
                    or not name
                    or quantity < 1
                    or quantity > 99
                    or unit_price < 0
                    or original_price < 0
                    or discount < 0
                    or discount > 100
                    or line_total != unit_price * quantity
                ):
                    raise ApiError("اطلاعات یکی از محصولات معتبر نیست.")

                items.append({
                    "product_id": product_id,
                    "name": name,
                    "quantity": quantity,
                    "unit_price": unit_price,
                    "original_price": original_price,
                    "discount": discount,
                    "line_total": line_total,
                })
                total += line_total

            with LOCK:
                order_id = NEXT_ORDER_ID
                NEXT_ORDER_ID += 1
                order = {
                    "id": order_id,
                    "code": make_tracking_code(),
                    "user_id": int(user["id"]),
                    "customer_name": customer_name,
                    "phone": str(user["phone"]),
                    "province": province,
                    "city": city,
                    "postal_code": postal_code,
                    "address": address,
                    "delivery": delivery,
                    "note": note,
                    "total": total,
                    "status": "new",
                    "created_at": now_text(),
                    "updated_at": now_text(),
                    "items": items,
                }
                ORDERS.insert(0, order)

            return {
                "message": "سفارش آزمایشی ثبت شد.",
                "tracking_code": order["code"],
                "order": order,
            }, 201, []

        if action == "track_order":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            code = str(data.get("code", "")).strip().upper()
            phone = normalize_phone(data.get("phone"))

            if not code or not valid_phone(phone):
                raise ApiError("کد سفارش و شماره موبایل معتبر نیست.")

            with LOCK:
                order = next(
                    (
                        item
                        for item in ORDERS
                        if item["code"] == code
                        and item["phone"] == phone
                    ),
                    None,
                )

            if not order:
                raise ApiError(
                    "سفارشی با این کد و شماره پیدا نشد.",
                    404,
                )

            return {"order": order.copy()}, 200, []

        if action == "admin_login":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            username = str(data.get("username", "")).strip().upper()
            password = str(data.get("password", ""))

            username_ok = hmac.compare_digest(username, ADMIN_USERNAME)
            password_ok = hmac.compare_digest(password, ADMIN_PASSWORD)

            if not username_ok or not password_ok:
                raise ApiError("نام کاربری یا رمز مدیریت نادرست است.", 401)

            sid = secrets.token_urlsafe(48)
            csrf = secrets.token_urlsafe(32)

            with LOCK:
                ADMIN_SESSIONS[sid] = {
                    "csrf": csrf,
                    "expires_at": now() + 2 * 60 * 60,
                }

            cookie = (
                f"dc_admin_session={sid}; Path=/; HttpOnly; "
                "SameSite=Lax; Max-Age=7200"
            )

            return {
                "message": "ورود مدیر انجام شد.",
                "csrf": csrf,
                "user": {
                    "id": 0,
                    "username": ADMIN_USERNAME.lower(),
                    "phone": "",
                    "wallet_balance": 0,
                    "is_admin": True,
                    "is_active": True,
                    "created_at": "",
                    "updated_at": "",
                },
            }, 200, [cookie]

        if action == "admin_logout":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            sid, session = self.admin_session()

            if session:
                self.require_csrf(session, "مدیر")

            if sid:
                with LOCK:
                    ADMIN_SESSIONS.pop(sid, None)

            cookie = (
                "dc_admin_session=; Path=/; HttpOnly; "
                "SameSite=Lax; Max-Age=0"
            )
            return {"message": "از مدیریت خارج شدید."}, 200, [cookie]

        if action == "admin_orders":
            if method != "GET":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            _, session = self.admin_session()
            if not session:
                raise ApiError("ابتدا وارد مدیریت شوید.", 401)

            search = str(query.get("q", [""])[0]).strip().lower()
            status_filter = str(
                query.get("status", ["all"])[0]
            )

            with LOCK:
                filtered = []

                for order in ORDERS:
                    if (
                        status_filter != "all"
                        and order["status"] != status_filter
                    ):
                        continue

                    haystack = " ".join([
                        str(order["code"]),
                        str(order["customer_name"]),
                        str(order["phone"]),
                        str(order["province"]),
                        str(order["city"]),
                    ]).lower()

                    if search and search not in haystack:
                        continue

                    filtered.append(order.copy())

            return {
                "orders": filtered,
                "csrf": str(session["csrf"]),
            }, 200, []

        if action == "admin_order_status":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            _, session = self.admin_session()
            self.require_csrf(session, "مدیر")

            order_id = int(data.get("id", 0))
            status_value = str(data.get("status", ""))
            allowed = {
                "new",
                "confirmed",
                "preparing",
                "shipped",
                "completed",
                "cancelled",
            }

            if order_id <= 0 or status_value not in allowed:
                raise ApiError("وضعیت سفارش معتبر نیست.")

            with LOCK:
                order = next(
                    (
                        item
                        for item in ORDERS
                        if int(item["id"]) == order_id
                    ),
                    None,
                )

                if not order:
                    raise ApiError("سفارش پیدا نشد.", 404)

                order["status"] = status_value
                order["updated_at"] = now_text()

            return {"message": "وضعیت سفارش تغییر کرد."}, 200, []

        if action == "admin_order_delete":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            _, session = self.admin_session()
            self.require_csrf(session, "مدیر")
            order_id = int(data.get("id", 0))

            with LOCK:
                index = next(
                    (
                        position
                        for position, item in enumerate(ORDERS)
                        if int(item["id"]) == order_id
                    ),
                    -1,
                )

                if index < 0:
                    raise ApiError("سفارش پیدا نشد.", 404)

                ORDERS.pop(index)

            return {"message": "سفارش آزمایشی حذف شد."}, 200, []

        if action == "admin_products_sync":
            if method != "POST":
                raise ApiError("روش درخواست مجاز نیست.", 405)

            _, session = self.admin_session()
            self.require_csrf(session, "مدیر")

            return {
                "message": (
                    "در نسخه بدون دیتابیس، محصولات داخل مرورگر "
                    "ذخیره می‌شوند."
                )
            }, 200, []

        raise ApiError("عملیات پیدا نشد.", 404)


def ask_password() -> str:
    try:
        value = getpass.getpass(
            "Password برنامه SMS Gateway "
            "(هنگام تایپ نمایش داده نمی‌شود): "
        )
        if value:
            return value
    except Exception:
        pass

    return input("Password برنامه SMS Gateway: ").strip()



def ask_sim_number() -> int:
    while True:
        value = input(
            "شماره سیم‌کارت ارسال پیامک (1 یا 2) [پیش‌فرض 1]: "
        ).strip()

        if value == "":
            return 1

        value = normalize_digits(value)

        if value in ("1", "2"):
            return int(value)

        print("فقط عدد 1 یا 2 وارد کنید.")



def ask_gateway_mode() -> str:
    while True:
        print("\nروش اتصال:")
        print("1) Local Server")
        print("2) Cloud Server")
        value = normalize_digits(input("انتخاب (1 یا 2) [پیش‌فرض 2]: ").strip())
        if value == "":
            return "cloud"
        if value == "1":
            return "local"
        if value == "2":
            return "cloud"
        print("فقط 1 یا 2 وارد کنید.")


def ask_cloud_device_id() -> str:
    while True:
        value = input("Cloud Device ID: ").strip()
        if re.fullmatch(r"[A-Za-z0-9_-]{10,150}", value):
            return value
        print("Device ID معتبر نیست.")


def validate_environment() -> list[str]:
    problems: list[str] = []

    if GATEWAY_MODE not in ("cloud", "local"):
        problems.append("SMS_GATE_MODE باید cloud یا local باشد.")

    if not GATEWAY_USERNAME:
        problems.append("SMS_GATE_USERNAME تنظیم نشده است.")

    if not GATEWAY_PASSWORD:
        problems.append("SMS_GATE_PASSWORD تنظیم نشده است.")

    if GATEWAY_MODE == "cloud" and not GATEWAY_DEVICE_ID:
        problems.append("SMS_GATE_DEVICE_ID تنظیم نشده است.")

    return problems


def main() -> None:
    problems = validate_environment()

    print("=" * 68)
    print("فروشگاه دیتاسنتر؛ نسخه عمومی GitHub + Render")
    print("=" * 68)
    print(
        "روش ارسال پیامک:",
        "Cloud Server" if GATEWAY_MODE == "cloud" else "Local Server",
    )
    print("سیم‌کارت ارسال پیامک:", f"SIM {SELECTED_SIM_NUMBER}")
    print("پورت:", PORT)

    if problems:
        print("\nهشدار تنظیمات:")
        for problem in problems:
            print("-", problem)
        print(
            "\nسایت اجرا می‌شود، اما ارسال کد تا تنظیم Environment Variables "
            "کار نخواهد کرد."
        )

    server = ThreadingHTTPServer((HOST, PORT), Handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nسرور متوقف شد.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

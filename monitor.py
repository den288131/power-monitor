#!/usr/bin/env python3
"""Мониторинг света через онлайн-статус робота-пылесоса в Xiaomi Cloud.

Команды:
  python monitor.py login         — ЛОКАЛЬНО: вход в Xiaomi, вывод токенов, региона и списка устройств
  python monitor.py check         — проверка статуса + уведомления (запускается в GitHub Actions)
  python monitor.py check --test  — только тестовое сообщение в Telegram с текущим статусом
  python monitor.py check --loop-minutes 345 --interval 60 — проверять раз в минуту ~5,75 ч (режим Actions)
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import random
import re
import string
import tempfile
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

REGIONS = ["de", "ru", "cn", "us", "sg", "in", "tw", "i2"]
STATE_FILE = Path(os.environ.get("STATE_FILE", "state.json"))
HTTP_TIMEOUT = 20
ERROR_ALERT_RUNS = 3          # сколько подряд неудачных проверок до предупреждения в Telegram
PASSWORD_RETRY_MIN = 60       # не чаще раза в час пробовать вход по паролю, если он уже не удался


def env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


# ───────────────────────── Xiaomi Cloud ─────────────────────────

class AuthError(Exception):
    pass


class TwoFactorRequired(AuthError):
    def __init__(self, url: str):
        super().__init__("Xiaomi требует подтвердить вход (2FA)")
        self.url = url


def rc4(key: bytes, data: bytes, drop: int = 0) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for n in range(drop + len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        if n >= drop:
            out.append(data[n - drop] ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _parse_account_json(text: str) -> dict:
    return json.loads(text.replace("&&&START&&&", "", 1))


class XiaomiCloud:
    """Неофициальный клиент Xiaomi Cloud (протокол как у Xiaomi-cloud-tokens-extractor)."""

    def __init__(self, user_id: str = "", ssecurity: str = "", service_token: str = ""):
        self.user_id, self.ssecurity, self.service_token = user_id, ssecurity, service_token
        self.http = requests.Session()
        rnd = "".join(random.choices(string.ascii_uppercase, k=13))
        self.http.headers["User-Agent"] = f"Android-7.1.1-1.0.0-ONEPLUS A3010-136-{rnd} APP/xiaomi.smarthome APPV/62830"
        self.device_id = "".join(random.choices(string.ascii_lowercase, k=6))

    @property
    def has_session(self) -> bool:
        return bool(self.user_id and self.ssecurity and self.service_token)

    # --- вход ---
    # ask_captcha(image_bytes) -> str и ask_email_code() -> str передаются только при локальном интерактивном входе.
    def login(self, username: str, password: str, ask_captcha=None, ask_email_code=None) -> None:
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        self.http.cookies.update({"sdkVersion": "accountsdk-18.8.15", "deviceId": self.device_id})

        r = self.http.get("https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true",
                          headers=h, cookies={"userId": username}, timeout=HTTP_TIMEOUT)
        sign = _parse_account_json(r.text).get("_sign")
        if not sign:
            raise AuthError("шаг 1 входа: не получен _sign")

        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        fields = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(password.encode()).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": username,
            "_sign": sign,
            "_json": "true",
        }
        d = _parse_account_json(self.http.post(url, headers=h, params=fields, allow_redirects=False,
                                               timeout=HTTP_TIMEOUT).text)
        for _ in range(3):
            if not d.get("captchaUrl"):
                break
            if not ask_captcha:
                raise AuthError("Xiaomi требует капчу при входе")
            cu = d["captchaUrl"]
            img = self.http.get(cu if cu.startswith("http") else "https://account.xiaomi.com" + cu, timeout=HTTP_TIMEOUT)
            fields["captCode"] = ask_captcha(img.content)
            d = _parse_account_json(self.http.post(url, headers=h, params=fields, allow_redirects=False,
                                                   timeout=HTTP_TIMEOUT).text)
            if d.get("code") == 87001:
                print("Неверная капча, ещё раз.")
                d["captchaUrl"] = d.get("captchaUrl") or cu

        if len(str(d.get("ssecurity") or "")) > 4:
            self.user_id, self.ssecurity = str(d["userId"]), d["ssecurity"]
            r = self.http.get(d["location"], headers=h, timeout=HTTP_TIMEOUT)
            token = r.cookies.get("serviceToken")
            if not token:
                raise AuthError("шаг 3 входа: не получен serviceToken")
            self.service_token = token
            return

        if d.get("notificationUrl"):
            nu = d["notificationUrl"]
            nu = nu if nu.startswith("http") else "https://account.xiaomi.com" + nu
            if not ask_email_code:
                raise TwoFactorRequired(nu)
            self._email_2fa(nu, ask_email_code)
            return
        code = d.get("code")
        hint = " — неверный логин или пароль" if code == 70016 else ""
        raise AuthError(f"code={code} {d.get('desc') or d.get('description') or ''}{hint}")

    def _cookie(self, name: str) -> str:
        for c in self.http.cookies:
            if c.name == name and c.value:
                return c.value
        return ""

    def _email_2fa(self, notification_url: str, ask_code) -> None:
        """Подтверждение входа кодом из почты (порт do_2fa_email_flow из Xiaomi-cloud-tokens-extractor)."""
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        acc = "https://account.xiaomi.com"
        self.http.get(notification_url, headers=h, timeout=HTTP_TIMEOUT)
        context = parse_qs(urlparse(notification_url).query)["context"][0]
        base = {"sid": "xiaomiio", "context": context, "_locale": "en_US"}
        self.http.get(f"{acc}/identity/list", params=base, headers=h, timeout=HTTP_TIMEOUT)
        self.http.post(f"{acc}/identity/auth/sendEmailTicket", headers=h, timeout=HTTP_TIMEOUT,
                       params={**base, "_dc": str(int(time.time() * 1000)), "mask": "0"},
                       data={"retry": "0", "icode": "", "_json": "true", "ick": self._cookie("ick")})

        code = ask_code()
        r = self.http.post(f"{acc}/identity/auth/verifyEmail", headers=h, timeout=HTTP_TIMEOUT,
                           params={**base, "_flag": "8", "_json": "true", "mask": "0"},
                           data={"_flag": "8", "ticket": code, "trust": "false", "_json": "true", "ick": self._cookie("ick")})
        if r.status_code != 200:
            raise AuthError(f"код не принят: HTTP {r.status_code}")
        try:
            jr = _parse_account_json(r.text)
            if jr.get("code") not in (0, None):
                raise AuthError(f"код не принят: {jr.get('tips') or jr.get('desc') or jr.get('code')}")
            finish = jr.get("location")
        except json.JSONDecodeError:
            finish = r.headers.get("Location")
            m = not finish and re.search(r'https://account\.xiaomi\.com/identity/result/check\?[^"\']+', r.text)
            finish = finish or (m.group(0) if m else None)
        if not finish:
            r0 = self.http.get(f"{acc}/identity/result/check", params=base, headers=h,
                               allow_redirects=False, timeout=HTTP_TIMEOUT)
            if r0.status_code in (301, 302):
                finish = r0.headers.get("Location")
        if not finish:
            raise AuthError("после кода не найден адрес завершения входа")

        end_url = finish
        if "identity/result/check" in finish:
            end_url = self.http.get(finish, headers=h, allow_redirects=False, timeout=HTTP_TIMEOUT).headers.get("Location")
        if not end_url:
            raise AuthError("не найден Auth2/end")
        r = self.http.get(end_url, headers=h, allow_redirects=False, timeout=HTTP_TIMEOUT)
        if r.status_code == 200 and "Xiaomi Account - Tips" in r.text:
            r = self.http.get(end_url, headers=h, allow_redirects=False, timeout=HTTP_TIMEOUT)
        try:
            self.ssecurity = json.loads(r.headers.get("extension-pragma") or "{}").get("ssecurity") or ""
        except json.JSONDecodeError:
            pass
        if not self.ssecurity:
            raise AuthError("после кода не получен ssecurity")

        sts = r.headers.get("Location")
        if not sts and "https://sts.api.io.mi.com/sts" in r.text:
            i = r.text.find("https://sts.api.io.mi.com/sts")
            sts = r.text[i:r.text.find('"', i)]
        if not sts:
            raise AuthError("не найден STS-редирект")
        self.http.get(sts, headers=h, timeout=HTTP_TIMEOUT)
        self.service_token = self._cookie("serviceToken")
        self.user_id = self.user_id or self._cookie("userId")
        if not (self.service_token and self.user_id):
            raise AuthError("после кода не получены serviceToken/userId")

    # --- подписанные/шифрованные запросы к API ---
    def _signed_nonce(self, nonce: str) -> str:
        return base64.b64encode(hashlib.sha256(base64.b64decode(self.ssecurity) + base64.b64decode(nonce)).digest()).decode()

    @staticmethod
    def _signature(path: str, signed_nonce: str, params: dict) -> str:
        parts = ["POST", path] + [f"{k}={v}" for k, v in params.items()] + [signed_nonce]
        return base64.b64encode(hashlib.sha1("&".join(parts).encode()).digest()).decode()

    def _api(self, region: str, path: str, params: dict) -> dict:
        host = "api.io.mi.com" if region == "cn" else f"{region}.api.io.mi.com"
        nonce = base64.b64encode(os.urandom(8) + int(time.time() / 60).to_bytes(4, "big")).decode()
        signed = self._signed_nonce(nonce)
        key = base64.b64decode(signed)

        fields = dict(params)
        fields["rc4_hash__"] = self._signature(path, signed, fields)
        fields = {k: base64.b64encode(rc4(key, str(v).encode(), 1024)).decode() for k, v in fields.items()}
        fields["signature"] = self._signature(path, signed, fields)
        fields["ssecurity"] = self.ssecurity
        fields["_nonce"] = nonce

        r = self.http.post(f"https://{host}/app{path}", params=fields, timeout=HTTP_TIMEOUT, headers={
            "Accept-Encoding": "identity",
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }, cookies={
            "userId": self.user_id, "serviceToken": self.service_token, "yetAnotherServiceToken": self.service_token,
            "locale": "en_GB", "timezone": "GMT+02:00", "is_daylight": "1", "dst_offset": "3600000",
            "channel": "MI_APP_STORE",
        })
        if r.status_code in (401, 403):
            raise AuthError(f"сессия Xiaomi недействительна (HTTP {r.status_code})")
        r.raise_for_status()
        try:
            data = json.loads(rc4(key, base64.b64decode(r.text), 1024))
        except Exception:
            text = r.text[:200]
            if "auth" in text.lower():
                raise AuthError(f"сессия Xiaomi недействительна: {text}")
            raise RuntimeError(f"не удалось расшифровать ответ Xiaomi: {text}")
        if data.get("code") not in (0, None):
            msg = f"Xiaomi API: code={data.get('code')} {data.get('message', '')}"
            raise AuthError(msg) if "auth" in msg.lower() else RuntimeError(msg)
        return data

    def devices(self, region: str) -> list[dict]:
        data = self._api(region, "/home/device_list", {
            "data": '{"getVirtualModel":true,"getHuamiDevices":1,"get_split_device":false,"support_smart_home":true}'
        })
        return (data.get("result") or {}).get("list") or []


def find_device(devices: list[dict], device_id: str) -> dict:
    if device_id:
        for d in devices:
            if str(d.get("did")) == device_id:
                return d
        raise RuntimeError(f"устройство {device_id} не найдено в аккаунте (проверь XIAOMI_DEVICE_ID и XIAOMI_REGION)")
    vacuums = [d for d in devices if "vacuum" in str(d.get("model", "")).lower()]
    if len(vacuums) == 1:
        return vacuums[0]
    names = ", ".join(f"{d.get('name')} [{d.get('did')}]" for d in devices) or "нет устройств"
    raise RuntimeError(f"не удалось однозначно выбрать пылесос, задай XIAOMI_DEVICE_ID. Устройства: {names}")


# ───────────────────────── Telegram ─────────────────────────

class TgError(RuntimeError):
    def __init__(self, code: int, description: str):
        super().__init__(f"Telegram: {code} {description}")
        self.code, self.description = code, description


def tg_api(method: str, payload: dict | None = None, timeout: float = HTTP_TIMEOUT):
    token = env("TELEGRAM_BOT_TOKEN")
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/{method}", json=payload or {}, timeout=timeout)
    except requests.RequestException as e:
        raise RuntimeError(f"Telegram недоступен: {type(e).__name__}") from None  # без URL — в нём токен
    try:
        data = r.json()
    except ValueError:
        raise TgError(r.status_code, r.text[:200]) from None
    if not data.get("ok"):
        raise TgError(data.get("error_code", r.status_code), data.get("description", ""))
    return data.get("result")


def tg_configured() -> bool:
    return bool(env("TELEGRAM_BOT_TOKEN") and env("TELEGRAM_CHAT_ID"))


def tg_send(text: str, **extra) -> dict | None:
    if not tg_configured():
        print(f"[telegram не настроен] {text}")
        return None
    res = tg_api("sendMessage", {"chat_id": env("TELEGRAM_CHAT_ID"), "text": text,
                                 "disable_web_page_preview": True, **extra})
    print(f"[telegram] {text}")
    return res


# ───────────────────────── Логика состояний ─────────────────────────

def step(state: dict, online: bool, now: float, threshold_s: float) -> tuple[dict, list[tuple]]:
    """Чистая функция: новое состояние + события ('lost', since) / ('restored', since_off, duration)."""
    st = dict(state)
    events: list[tuple] = []
    status = st.get("status")
    if online:
        st["offline_candidate"] = None
        if status == "offline":
            events.append(("restored", st["since"], now - st["since"]))
            st.update(status="online", since=now)
        elif status is None:
            st.update(status="online", since=now)
    elif status != "offline":
        cand = st.get("offline_candidate") or now
        st["offline_candidate"] = cand
        if now - cand >= threshold_s:
            events.append(("lost", cand))
            st.update(status="offline", since=cand, offline_candidate=None)
    return st, events


def _tz():
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(env("TIMEZONE", "Europe/Moscow"))
    except Exception:
        return timezone.utc


def fmt_time(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, _tz())
    today = datetime.now(_tz()).date()
    return dt.strftime("%H:%M") if dt.date() == today else dt.strftime("%d.%m %H:%M")


def fmt_dur(sec: float) -> str:
    m = int(max(sec, 0) // 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return f"{d} д {h} ч {m} мин"
    return f"{h} ч {m} мин" if h else f"{m} мин"


def event_text(ev: tuple, now: float) -> str:
    if ev[0] == "lost":
        return f"❌ Света нет\nРобот офлайн примерно с {fmt_time(ev[1])}."
    return f"✅ Свет есть\nРобот снова онлайн. Не было примерно {fmt_dur(ev[2])} (с {fmt_time(ev[1])})."


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text("utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=1), "utf-8")


# ───────────────────────── История и сводки ─────────────────────────

HISTORY_DAYS = 40
WEEKDAYS = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"]


def record_events(state: dict, events: list[tuple], now: float) -> None:
    """Пишет отключения в state['history'] как [{'start', 'end'|None}]."""
    hist = state.setdefault("history", [])
    for ev in events:
        if ev[0] == "lost":
            hist.append({"start": ev[1], "end": None})
        else:
            open_ = [h for h in hist if h["end"] is None]
            if open_:
                open_[-1]["end"] = now
            else:
                hist.append({"start": ev[1], "end": now})
    cutoff = now - HISTORY_DAYS * 86400
    state["history"] = [h for h in hist if (h["end"] or now) >= cutoff]


def _boundary(d) -> float:
    """Граница суток для сводок: d в SUMMARY_HOUR:00 (по умолчанию 21:00)."""
    return datetime(d.year, d.month, d.day, int(env("SUMMARY_HOUR", "21")), tzinfo=_tz()).timestamp()


def _last_boundary(now: float):
    """Последняя прошедшая граница сводок: (timestamp, дата)."""
    today = datetime.fromtimestamp(now, _tz()).date()
    d = today if now >= _boundary(today) else today - timedelta(days=1)
    return _boundary(d), d


def outages_in(hist: list[dict], start: float, end: float, now: float) -> list[tuple[float, float, bool]]:
    """Отключения, пересекающие [start, end), обрезанные по границам: (from, to, продолжается)."""
    out = []
    for h in sorted(hist, key=lambda h: h["start"]):
        s, e = h["start"], h["end"] if h["end"] is not None else min(now, end)
        if s < end and e > start:
            out.append((max(s, start), min(e, end), h["end"] is None and e >= now))
    return out


def _period_end(state: dict, boundary: float) -> float | None:
    """Конец периода сводки: граница, а если в этот момент света не было — момент его возвращения.
    None — свет ещё не вернулся, сводку откладываем."""
    if state.get("status") == "offline":
        return None
    for h in state.get("history", []):
        if h["start"] < boundary and h["end"] is not None and h["end"] > boundary:
            return h["end"]
    return boundary


def _point(ts: float, ref: float) -> str:
    """HH:MM, а если день отличается от дня ref — «вс 22:10»."""
    dt = datetime.fromtimestamp(ts, _tz())
    if dt.date() == datetime.fromtimestamp(ref, _tz()).date():
        return dt.strftime("%H:%M")
    return f"{WEEKDAYS[dt.weekday()]} {dt:%H:%M}"


def _since_note(since: float | None, start: float) -> str:
    if since and since > start:
        return f"\nℹ️ Учёт ведётся с {datetime.fromtimestamp(since, _tz()):%d.%m %H:%M}, раньше данных нет."
    return ""


def period_summary(hist: list[dict], start: float, end: float, now: float, title: str,
                   since: float | None = None, ref: float | None = None) -> str:
    items = outages_in(hist, start, end, now)
    note = _since_note(since, start)
    if not items:
        return f"{title}\nОтключений не было ✅{note}"
    ref = ref or end
    total = sum(b - a for a, b, _ in items)
    lines = [title, f"Отключений: {len(items)}, без света {fmt_dur(total)} ({total / (end - start):.0%} времени)"]
    for a, b, ongoing in items:
        lines.append(f"• {_point(a, ref)}–{'…сейчас' if ongoing else _point(b, ref)} ({fmt_dur(b - a)})")
    return "\n".join(lines) + note


def day_summary(hist: list[dict], start: float, end: float, day, now: float, since: float | None = None) -> str:
    if end - start > 1.5 * 86400:  # пропущенные сутки (мониторинг не работал) — честно показываем период
        title = f"📊 Сводка за {fmt_time(start)} – {fmt_time(end)}"
    else:
        title = f"📊 Сводка за сутки: {WEEKDAYS[day.weekday()]} {day:%d.%m}"
    return period_summary(hist, start, end, now, title, since, ref=_boundary(day))


def week_summary(hist: list[dict], start: float, end: float, last_day, now: float, since: float | None = None) -> str:
    first = last_day - timedelta(days=6)
    title = f"📅 Сводка за неделю {first:%d.%m}–{last_day:%d.%m}"
    items = outages_in(hist, start, end, now)
    note = _since_note(since, start)
    if not items:
        return f"{title}\nОтключений не было ✅{note}"
    total = sum(b - a for a, b, _ in items)
    lines = [title, f"Отключений: {len(items)}, без света {fmt_dur(total)} ({total / (end - start):.0%} времени)"]
    for i in range(7):
        d = first + timedelta(days=i)
        d_start = max(start, _boundary(d) - 86400)
        d_end = end if i == 6 else _boundary(d)
        di = outages_in(hist, d_start, d_end, now) if d_end > d_start else []
        dur = sum(b - a for a, b, _ in di)
        lines.append(f"{WEEKDAYS[d.weekday()]} {d:%d.%m}: " + (f"{fmt_dur(dur)} ({len(di)} шт.)" if di else "—"))
    return "\n".join(lines) + note


def due_summaries(state: dict, now: float) -> list[tuple[dict, str | None]]:
    """Какие сводки пора отправить: [(что записать в state после отправки, текст или None — пометить без отправки)].
    Каждый день в SUMMARY_HOUR — за сутки, в SUMMARY_WEEKDAY (0=пн … 6=вс) — ещё и за неделю.
    Если в этот момент света нет, сводка ждёт его возвращения и включает отключение целиком."""
    if "status" not in state:
        return []
    boundary, day = _last_boundary(now)
    key = day.isoformat()
    hist, since = state.get("history", []), state.get("history_since")
    out = []
    plans = [("daily", 1, day_summary)]
    if day.weekday() == int(env("SUMMARY_WEEKDAY", "6")):
        plans.append(("weekly", 7, week_summary))
    for name, days, make in plans:
        if state.get(f"last_{name}") == key:
            continue
        end = _period_end(state, boundary)
        if end is None:
            continue
        # с конца прошлой сводки (стык без дыр и двойного учёта), но не раньше недели назад
        prev = state.get(f"{name}_from") or 0
        start = prev if boundary - 7 * 86400 <= prev < boundary else boundary - days * 86400
        upd = {f"last_{name}": key, f"{name}_from": end}
        text = None if since and since >= end else make(hist, start, end, day, now, since)
        out.append((upd, text))
    return out


def send_summaries(state: dict, now: float) -> None:
    for upd, text in due_summaries(state, now):
        try:
            if text:
                tg_send(text)
            state.update(upd)
        except Exception as e:
            print(f"Не удалось отправить сводку: {e}")


# ───────────────────────── Бот: кнопки и закреп ─────────────────────────

BTN_DAY, BTN_WEEK, BTN_STATUS = "📊 Сутки", "📅 Неделя", "💡 Статус"
KEYBOARD = {"keyboard": [[{"text": BTN_DAY}, {"text": BTN_WEEK}], [{"text": BTN_STATUS}]],
            "resize_keyboard": True, "is_persistent": True}
BOT_SETUP_VERSION = 1


def setup_bot(state: dict) -> None:
    """Один раз: меню команд и постоянные кнопки внизу чата."""
    if not tg_configured() or state.get("bot_setup") == BOT_SETUP_VERSION:
        return
    try:
        tg_api("setMyCommands", {"commands": [
            {"command": "day", "description": "Сводка за последние сутки"},
            {"command": "week", "description": "Сводка за последние 7 дней"},
            {"command": "status", "description": "Есть ли сейчас свет"},
        ]})
        tg_send("🔘 Добавлены кнопки внизу чата: сводка за сутки, за неделю и текущий статус.\n"
                "Сколько есть или нет света — в закреплённом сообщении вверху чата.", reply_markup=KEYBOARD)
        state["bot_setup"] = BOT_SETUP_VERSION
    except Exception as e:
        print(f"Не удалось настроить кнопки бота: {e}")


def status_text(state: dict, now: float) -> str:
    status, since = state.get("status"), state.get("since")
    if status not in ("online", "offline") or not since:
        return "❔ Статус света пока неизвестен"
    if status == "offline":
        lines = [f"🔌 Света нет {fmt_dur(now - since)}", f"с {fmt_time(since)}"]
    else:
        lines = [f"💡 Свет есть {fmt_dur(now - since)}", f"с {fmt_time(since)}"]
        cand = state.get("offline_candidate")
        if cand:
            lines.append(f"⏳ робот офлайн с {fmt_time(cand)}, ждём подтверждения")
    if (state.get("problem") or {}).get("count"):
        lines.append("⚠️ нет связи с Xiaomi — статус может быть устаревшим")
    return "\n".join(lines)


def update_pin(state: dict, now: float) -> None:
    """Держит закреплённое сообщение со статусом света в актуальном виде."""
    if not tg_configured() or "status" not in state:
        return
    chat = env("TELEGRAM_CHAT_ID")
    text = f"{status_text(state, now)}\n🕐 обновлено {datetime.fromtimestamp(now, _tz()):%H:%M}"
    if state.get("pin_text") == text:
        return
    mid = state.get("pin_id")
    try:
        if mid:
            try:
                tg_api("editMessageText", {"chat_id": chat, "message_id": mid, "text": text})
            except TgError as e:
                if "not modified" not in e.description:
                    print(f"Закреп не обновился ({e.description}), создаю новый")
                    try:
                        tg_api("unpinChatMessage", {"chat_id": chat, "message_id": mid})
                    except Exception:
                        pass
                    mid = None
        if not mid:
            mid = tg_api("sendMessage", {"chat_id": chat, "text": text, "disable_notification": True})["message_id"]
            tg_api("pinChatMessage", {"chat_id": chat, "message_id": mid, "disable_notification": True})
            state["pin_id"] = mid
        state["pin_text"] = text
    except Exception as e:
        print(f"Не удалось обновить закреп: {e}")


def handle_message(state: dict, msg: dict) -> None:
    if str((msg.get("chat") or {}).get("id")) != env("TELEGRAM_CHAT_ID"):
        return  # отвечаем только владельцу
    text = (msg.get("text") or "").strip()
    cmd = text.split("@")[0].lower() if text.startswith("/") else text
    now = time.time()
    hist, since = state.get("history", []), state.get("history_since")
    if cmd in (BTN_DAY, "/day"):
        tg_send(period_summary(hist, now - 86400, now, now, "📊 Сводка за последние 24 ч", since), reply_markup=KEYBOARD)
    elif cmd in (BTN_WEEK, "/week"):
        today = datetime.fromtimestamp(now, _tz()).date()
        start = _boundary(today - timedelta(days=6)) - 86400
        tg_send(week_summary(hist, start, now, today, now, since), reply_markup=KEYBOARD)
    elif cmd in (BTN_STATUS, "/status"):
        tg_send(status_text(state, now), reply_markup=KEYBOARD)
    elif cmd == "/start":
        tg_send("Я слежу за светом дома по роботу-пылесосу. Кнопки внизу: сводка за сутки, за неделю, "
                "текущий статус.", reply_markup=KEYBOARD)
    else:
        tg_send("Не понял 🙂 Воспользуйся кнопками внизу.", reply_markup=KEYBOARD)


def poll_commands(state: dict, until: float) -> None:
    """Слушает сообщения боту (long polling) до момента until."""
    if not tg_configured():
        time.sleep(max(0.0, until - time.time()))
        return
    while True:
        left = until - time.time()
        if left <= 1:
            time.sleep(max(0.0, left))
            return
        wait = int(min(left, 50))
        try:
            updates = tg_api("getUpdates", {"offset": state.get("tg_offset", 0), "timeout": wait,
                                            "allowed_updates": ["message"]}, timeout=wait + 15)
        except TgError as e:
            if e.code == 409 and "webhook" in e.description.lower():
                print("У бота включён webhook от старой программы — отключаю, чтобы получать кнопки")
                try:
                    tg_api("deleteWebhook")
                except Exception as e2:
                    print(f"Не удалось отключить webhook: {e2}")
                    time.sleep(min(left, 10))
                continue
            print(f"getUpdates: {e}")
            time.sleep(min(left, 10))
            continue
        except Exception as e:
            print(f"getUpdates: {e}")
            time.sleep(min(left, 10))
            continue
        for u in updates or []:
            state["tg_offset"] = u["update_id"] + 1
            try:
                handle_message(state, u.get("message") or {})
            except Exception as e:
                print(f"Не удалось ответить на сообщение: {e}")
        if updates:
            save_state(state)


# ───────────────────────── Команды ─────────────────────────

_cloud: XiaomiCloud | None = None  # переиспользуем сессию между проверками в цикле


def fetch_device(state: dict, now: float) -> dict:
    global _cloud
    region = env("XIAOMI_REGION", "de").lower()
    device_id = env("XIAOMI_DEVICE_ID")
    user, pw = env("XIAOMI_USERNAME"), env("XIAOMI_PASSWORD")
    if _cloud is None:
        _cloud = XiaomiCloud(env("XIAOMI_USER_ID"), env("XIAOMI_SSECURITY"), env("XIAOMI_SERVICE_TOKEN"))
    cloud = _cloud

    if cloud.has_session:
        try:
            return find_device(cloud.devices(region), device_id)
        except AuthError as e:
            print(f"Сессия не подошла: {e}")
            if not (user and pw):
                raise
    if not (user and pw):
        raise AuthError("не заданы ни токены (XIAOMI_SERVICE_TOKEN и др.), ни логин/пароль")

    last = state.get("last_password_login", 0)
    if now - last < PASSWORD_RETRY_MIN * 60:
        raise AuthError("вход по паролю недавно не удался, следующая попытка позже")
    state["last_password_login"] = now
    _cloud = cloud = XiaomiCloud()
    try:
        cloud.login(user, pw)
    except TwoFactorRequired:
        raise AuthError("Xiaomi требует подтвердить вход с сервера GitHub. "
                        "Запусти локально `python monitor.py login` и обнови секреты с токенами") from None
    state["last_password_login"] = 0
    print("Вход по паролю успешен (для стабильности лучше прописать свежие токены в секреты)")
    return find_device(cloud.devices(region), device_id)


def report_problem(state: dict, kind: str, text: str) -> None:
    p = state.get("problem") or {"count": 0, "alerted": False, "since": time.time()}
    p["count"] += 1
    p["kind"] = kind
    need = 1 if kind == "auth" else ERROR_ALERT_RUNS
    if not p["alerted"] and p["count"] >= need:
        try:
            tg_send(f"⚠️ Мониторинг света не может проверить статус\n{text}\n"
                    "Пока это не исправлено, уведомления о свете не приходят.")
            p["alerted"] = True
        except Exception as e:
            print(f"Не удалось отправить предупреждение: {e}")
    state["problem"] = p


def check_once(state: dict, threshold: float) -> dict:
    """Одна проверка: обновляет state, шлёт уведомления. Возвращает устройство или {} при ошибке."""
    now = time.time()
    try:
        dev = fetch_device(state, now)
    except AuthError as e:
        print(f"Ошибка авторизации: {e}")
        report_problem(state, "auth", f"Ошибка входа в Xiaomi: {e}")
        return {}
    except Exception as e:
        print(f"Ошибка проверки: {type(e).__name__}: {e}")
        report_problem(state, "error", f"{type(e).__name__}: {e}")
        return {}

    online = bool(dev.get("isOnline"))
    stamp = datetime.fromtimestamp(now, _tz()).strftime("%H:%M:%S")
    print(f"{stamp} {dev.get('name')} [{dev.get('did')}]: {'online' if online else 'OFFLINE'}")

    if (state.get("problem") or {}).get("alerted"):
        try:
            tg_send("✅ Мониторинг света снова работает.")
        except Exception as e:
            print(f"Не удалось отправить сообщение: {e}")
    state.pop("problem", None)
    state.setdefault("history_since", now)

    new_state, events = step(state, online, now, threshold)
    try:
        for ev in events:
            tg_send(event_text(ev, now))
        state.clear()
        state.update(new_state)  # продвигаем состояние только если уведомления ушли
        record_events(state, events, now)
    except Exception as e:
        print(f"Не удалось отправить уведомление, повторим при следующей проверке: {e}")
    state["last_check"] = now
    return dev


def heartbeat() -> None:
    """Отметка «мониторинг жив» для внешнего сторожа (healthchecks.io). Ошибки игнорируются."""
    url = env("HEALTHCHECK_URL")
    if not url:
        return
    try:
        requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"heartbeat не отправлен: {type(e).__name__}")


def cmd_check(test: bool, loop_minutes: float, interval: float) -> int:
    threshold = float(env("OFFLINE_THRESHOLD_MIN", "5")) * 60
    state = load_state()

    if test:  # тест только сообщает статус и не трогает сохранённое состояние
        try:
            dev = fetch_device(state, time.time())
        except Exception as e:
            tg_send(f"🔧 Тест: ошибка проверки — {type(e).__name__}: {e}")
            return 1
        online = bool(dev.get("isOnline"))
        tg_send(f"🔧 Тест мониторинга\n«{dev.get('name')}»: {'онлайн — свет есть' if online else 'офлайн'}\n"
                f"Сохранённый статус: {state.get('status') or 'нет'}, порог {int(threshold // 60)} мин.")
        now = time.time()
        tg_send(period_summary(state.get("history", []), now - 86400, now, now,
                               "📊 Сводка за последние 24 ч", state.get("history_since")))
        return 0

    deadline = time.time() + loop_minutes * 60
    setup_bot(state)
    while True:
        started = time.time()
        check_once(state, threshold)
        send_summaries(state, time.time())
        update_pin(state, time.time())
        save_state(state)
        heartbeat()
        if started + interval > deadline:
            return 0
        # вместо паузы слушаем кнопки бота — ответ приходит сразу
        poll_commands(state, until=started + interval)


def cmd_login() -> int:
    user = env("XIAOMI_USERNAME") or input("Логин Xiaomi (email / телефон / ID): ").strip()
    pw = env("XIAOMI_PASSWORD") or getpass.getpass("Пароль Xiaomi: ")
    def ask_captcha(img: bytes) -> str:
        path = Path(tempfile.gettempdir()) / "xiaomi_captcha.jpg"
        path.write_bytes(img)
        print(f"\nXiaomi просит капчу. Картинка: {path}")
        try:
            os.startfile(path)  # Windows: откроет картинку
        except Exception:
            pass
        return input("Введи символы с картинки (с учётом регистра): ").strip()

    def ask_email_code() -> str:
        print("\nXiaomi просит подтвердить вход. Код отправлен на почту аккаунта.")
        return input("\nКод из письма: ").strip()

    cloud = XiaomiCloud()
    try:
        cloud.login(user, pw, ask_captcha, ask_email_code)
    except AuthError as e:
        print(f"\nВход не удался: {e}")
        if isinstance(e, TwoFactorRequired):
            print(f"Ссылка подтверждения: {e.url}")
        return 1

    print("\nВход выполнен. Ищу устройства по регионам…")
    found_region = ""
    for region in REGIONS:
        try:
            devs = cloud.devices(region)
        except Exception as e:
            print(f"  {region}: ошибка ({e})")
            continue
        if not devs:
            continue
        found_region = found_region or region
        print(f"\n  Регион {region}:")
        for d in devs:
            print(f"    did={d.get('did'):<14} {'online ' if d.get('isOnline') else 'OFFLINE'}  {d.get('model'):<28} {d.get('name')}")

    print("\n──────── Добавь в GitHub → Settings → Secrets and variables → Actions → Secrets ────────")
    print(f"XIAOMI_USER_ID        = {cloud.user_id}")
    print(f"XIAOMI_SSECURITY      = {cloud.ssecurity}")
    print(f"XIAOMI_SERVICE_TOKEN  = {cloud.service_token}")
    print(f"XIAOMI_REGION         = {found_region or '(устройства не найдены)'}")
    print("XIAOMI_DEVICE_ID      = did пылесоса из списка выше")
    print("──────────────────────────────────────────────────────────────────────────────────────")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("login", help="локальный вход: токены, регион, список устройств")
    c = sub.add_parser("check", help="проверка статуса и уведомления")
    c.add_argument("--test", action="store_true", help="отправить тестовое сообщение с текущим статусом")
    c.add_argument("--loop-minutes", type=float, default=0, help="проверять в цикле столько минут (0 — одна проверка)")
    c.add_argument("--interval", type=float, default=60, help="пауза между проверками в цикле, сек")
    a = p.parse_args()
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
    return cmd_login() if a.cmd == "login" else cmd_check(a.test, a.loop_minutes, a.interval)


if __name__ == "__main__":
    sys.exit(main())

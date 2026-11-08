#!/usr/bin/env python3
"""Сторож: проверяет через GitHub API, что основной workflow (monitor.yml) включён и работает.

Пишет в Telegram один раз при проблеме и один раз при восстановлении. Без внешних зависимостей.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = Path(os.environ.get("WATCHDOG_STATE", "watchdog.json"))
STALE_MIN = float(os.environ.get("WATCHDOG_STALE_MIN", "30"))  # сколько минут без активного запуска считать проблемой
ACTIVE = {"in_progress", "queued", "waiting", "pending", "requested"}


def gh(path: str) -> dict:
    req = urllib.request.Request(f"https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}{path}", headers={
        "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def tg_send(text: str) -> None:
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        print(f"[telegram не настроен] {text}")
        return
    body = json.dumps({"chat_id": chat, "text": text}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=20).close()
    except Exception as e:
        raise RuntimeError(f"Telegram: {type(e).__name__}") from None  # без URL — в нём токен
    print(f"[telegram] {text}")


def diagnose(workflow: dict, runs: list[dict], now: datetime) -> str | None:
    """Чистая функция: текст проблемы или None, если всё в порядке."""
    if workflow.get("state") != "active":
        return f"GitHub отключил workflow мониторинга (состояние: {workflow.get('state')})."
    if any(r.get("status") in ACTIVE for r in runs):
        return None
    if not runs:
        return "У workflow мониторинга нет ни одного запуска."
    last = max(datetime.fromisoformat(r["updated_at"].replace("Z", "+00:00")) for r in runs)
    minutes = (now - last).total_seconds() / 60
    if minutes > STALE_MIN:
        return f"Мониторинг не запускался уже {int(minutes)} мин (последний запуск закончился в {last:%H:%M} UTC)."
    return None


def main() -> int:
    try:
        state = json.loads(STATE_FILE.read_text("utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        state = {}

    try:
        wf = gh("/actions/workflows/monitor.yml")
        runs = gh("/actions/workflows/monitor.yml/runs?per_page=10").get("workflow_runs", [])
        runs = [r for r in runs if r.get("event") != "workflow_dispatch" or r.get("status") in ACTIVE]
        problem = diagnose(wf, runs, datetime.now(timezone.utc))
    except Exception as e:
        print(f"GitHub API недоступен: {type(e).__name__}: {e}")
        return 0

    print(problem or "Мониторинг работает.")
    try:
        if problem and not state.get("alerted"):
            tg_send(f"⚠️ Сторож: мониторинг света не работает\n{problem}\n"
                    "Открой Actions в репозитории power-monitor и включи workflow (Enable workflow).")
            state["alerted"] = True
        elif not problem and state.get("alerted"):
            tg_send("✅ Сторож: мониторинг света снова работает.")
            state["alerted"] = False
    except Exception as e:
        print(f"Не удалось отправить сообщение: {e}")
    STATE_FILE.write_text(json.dumps(state), "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

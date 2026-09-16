#!/usr/bin/env python3
"""Чтение и поиск логов Chatium с отдельным временным ключом."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

ACTIONS = ("list", "count")
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_CHARS = 30000
MAX_CELL_CHARS = 2000
GRANT_TTL_SECONDS = 12 * 60 * 60


class LogsError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # Do not forward the account credential to a login page or another host.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def account_host(value):
    host = value.removeprefix("https://").rstrip("/").lower()
    if len(host) > 253 or "." not in host or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise argparse.ArgumentTypeError("Укажите домен аккаунта без пути, порта и параметров.")
    return host


def write_grant_record(path, record):
    """Replace this host's credential atomically, keeping the new file private."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".grant-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(record, out)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def access_status(record):
    status = {"account": record["account"], "state": record["state"]}
    if "expiresAt" in record:
        status["expiresAt"] = datetime.fromtimestamp(record["expiresAt"], timezone.utc).isoformat()
    return status


def private_write(path, text):
    """Create a private file without overwriting an existing file or symlink."""
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as out:
        out.write(text)
    return str(path.resolve())


def grant_path(host):
    return Path.home() / ".config/chatium/logs" / (host + ".grant.json")


def grant_endpoint(key):
    if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{32}", key):
        raise LogsError("Некорректный идентификатор разрешения.")
    return "/app/dev/agent-logs~" + key


def validate_access_key(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise LogsError("Некорректный ключ доступа к логам; повторите --login.")
    return value


def saved_grant(host):
    path = grant_path(host)
    if not path.exists():
        return {"account": host, "state": "missing"}
    if path.stat().st_mode & 0o077:
        raise LogsError("Файл доступа доступен другим пользователям; задайте chmod 600.")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("account") != host:
        raise LogsError("Некорректный файл доступа; повторите --login.")
    if record.get("state") in ("revoked", "expired"):
        return record
    if record.get("authType") != "header-key":
        return {"account": host, "state": "unsupported"}
    if (record.get("endpoint") != grant_endpoint(record.get("grantKey")) or
            type(record.get("expiresAt")) not in (int, float) or
            type(record.get("createdAt")) not in (int, float) or
            not math.isfinite(record["expiresAt"]) or not math.isfinite(record["createdAt"]) or
            not 0 < record["expiresAt"] - record["createdAt"] <= GRANT_TTL_SECONDS):
        raise LogsError("Некорректный срок или маршрут доступа; повторите --login.")
    if time.time() >= record["expiresAt"]:
        record.pop("accessKey", None)
        record["state"] = "expired"
        write_grant_record(path, record)
    elif time.time() < record["createdAt"]:
        raise LogsError("Проверьте часы компьютера и повторите --login.")
    else:
        record["accessKey"] = validate_access_key(record.get("accessKey"))
        record["state"] = "active"
    return record


def grant_status(record):
    return {**access_status(record), "mode": "header-key", "grantKey": record.get("grantKey")}


def post_json(host, path, body, *, access_key=None):
    # All endpoints are constructed locally; no server-supplied URL receives a key.
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if access_key is not None:
        headers["X-Chatium-Logs-Key"] = validate_access_key(access_key)
    request = urllib.request.Request("https://" + account_host(host) + path,
                                     data=json.dumps(body, allow_nan=False).encode(), headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=45) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise LogsError(f"HTTP {error.code}. Проверьте домен аккаунта и доступ; при истёкшем доступе подключитесь заново.") from None
    except (urllib.error.URLError, TimeoutError):
        raise LogsError("Не удалось связаться с API аккаунта.") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise LogsError("Слишком большой ответ; сузьте запрос.")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise LogsError("Получен ответ в неожиданном формате. Проверьте доступность чтения логов в аккаунте.") from None
    if not isinstance(result, dict):
        raise LogsError("Некорректный ответ API.")
    return result


def login_grant(host, open_browser=True):
    previous = saved_grant(host)
    if previous["state"] == "active":
        raise LogsError("Доступ уже активен. Используйте его или выполните --logout перед новым --login.")
    access_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(access_key.encode()).hexdigest()
    request = post_json(host, "/app/dev/log-access~request", {"keyHash": key_hash})
    if request.get("success") is not True:
        raise LogsError("Не удалось создать запрос доступа.")
    key = request.get("grantKey")
    grant_endpoint(key)
    user_code = request.get("userCode", "")
    if not isinstance(user_code, str) or not re.fullmatch(r"[A-F0-9]{8}", user_code):
        raise LogsError("Некорректный ответ выдачи доступа.")
    # Construct the approval URL for this host, ignoring arbitrary remote URLs.
    query = {"grantKey": key}
    url = "https://" + host + "/app/dev/log-access?" + urllib.parse.urlencode(query)
    print(f"\nКод подключения: {user_code[:4]}-{user_code[4:]}\n"
          f"Аккаунт: {host}\nОткрыть для подтверждения: {url}\n"
          "Выберите срок доступа: 2, 6 или 12 часов, затем нажмите «Разрешить доступ».\n"
          "Код действует 5 минут. Оставьте этот терминал открытым до подтверждения.\n",
          file=sys.stderr, flush=True)
    if open_browser:
        webbrowser.open(url)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        time.sleep(5)
        result = post_json(host, "/app/dev/log-access~status", {"grantKey": key}, access_key=access_key)
        if result.get("state") == "pending":
            continue
        if result.get("success") is not True:
            raise LogsError("Запрос отклонён, истёк или доступ удалён. Повторите --login.")
        now = time.time()
        expires_raw = result.get("expiresAt")
        if not isinstance(expires_raw, str):
            raise LogsError("API не указал срок действия доступа.")
        try:
            expires = datetime.fromisoformat(expires_raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise LogsError("Некорректный срок действия доступа в ответе API.") from None
        if result.get("grantKey") != key or result.get("endpoint") != grant_endpoint(key) or not now < expires <= now + GRANT_TTL_SECONDS:
            raise LogsError("Некорректный срок или маршрут выданного доступа; проверьте часы компьютера.")
        record = {"account": host, "state": "active", "grantKey": key, "endpoint": grant_endpoint(key),
                  "authType": "header-key", "accessKey": access_key, "createdAt": now, "expiresAt": expires}
        write_grant_record(grant_path(host), record)
        return {"success": True, **grant_status(record)}
    raise LogsError("Время подтверждения истекло. Повторите --login.")


def fetch_grant_logs(host, record, action, body):
    if action not in ("list", "count"):
        raise LogsError("Ограниченный доступ поддерживает только list и count.")
    result = post_json(host, grant_endpoint(record["grantKey"]), {"action": action, **body},
                       access_key=record["accessKey"])
    if result.get("success") is not True or (action == "list" and not isinstance(result.get("rows"), list)):
        # Do not echo an error body that might contain credentials from a proxy.
        raise LogsError("API отклонил запрос. Проверьте срок доступа, фильтры и окно до 24 часов; SQL запрещён.")
    return result


def logout_grant(host, record):
    if record["state"] == "active":
        status = post_json(host, "/app/dev/log-access~status", {"grantKey": record["grantKey"]},
                           access_key=record["accessKey"])
        # A developer may already have deleted the row. Verify that on the server
        # before discarding the local key; network failures still preserve it.
        if status.get("success") is True:
            result = post_json(host, grant_endpoint(record["grantKey"]) + "/revoke", {},
                               access_key=record["accessKey"])
            if result.get("success") is not True:
                raise LogsError("Не удалось подтвердить отзыв. Отзовите доступ через страницу управления разрешениями в аккаунте.")
        elif status.get("state") != "invalid_request":
            raise LogsError("Не удалось проверить состояние доступа; повторите --logout.")
    record.pop("accessKey", None)
    record["state"] = "revoked"
    write_grant_record(grant_path(host), record)
    return {"success": True, **grant_status(record)}


def compact_result(result, host, action, body, output_path=None):
    """Bound model output; full data and original metadata remain in --output."""
    clipped = 0

    def compact(value):
        nonlocal clipped
        if isinstance(value, str) and len(value) > MAX_CELL_CHARS:
            clipped += 1
            return value[:MAX_CELL_CHARS] + " [client truncated]"
        if isinstance(value, dict):
            return {k: compact(v) for k, v in value.items() if v is not None and v != "" and v != []}
        if isinstance(value, list):
            return [compact(v) for v in value]
        return value

    summary = {"account": host, "action": action, "request": body,
               "rowsReceived": len(result.get("rows", [])), "rowsShown": 0,
               "outputTruncated": False, "fullResponseFile": output_path}
    out = compact({k: v for k, v in result.items() if k != "rows"})
    out["client"] = summary
    if "rows" in result:
        out["rows"] = []
        for row in result["rows"]:
            item = compact(row)
            out["rows"].append(item)
            if len(json.dumps(out, ensure_ascii=False)) > MAX_OUTPUT_CHARS - 1000:
                out["rows"].pop()
                break
        summary["rowsShown"] = len(out["rows"])
    summary["clippedCells"] = clipped
    summary["outputTruncated"] = bool(clipped or summary["rowsShown"] < summary["rowsReceived"])
    # Metadata/facets can also be large; keep a valid JSON envelope.
    if len(json.dumps(out, ensure_ascii=False)) > MAX_OUTPUT_CHARS:
        summary["outputTruncated"] = True
        summary["rowsShown"] = 0
        out = {"success": True, "client": {k: v for k, v in summary.items() if k != "request"}}
    return out


def make_body(action, filters, minutes=15, limit=50, now_ms=None):
    if action not in ACTIONS:
        raise LogsError("Доступны только list и count.")
    if not isinstance(filters, dict) or "filters" in filters:
        raise LogsError("Передайте сам JSON-объект фильтров, без внешнего ключа filters.")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise LogsError("limit должен быть целым числом от 1 до 500.")
    if not math.isfinite(minutes) or not 0 < minutes <= 1440:
        raise LogsError("minutes: положительное число, не больше 1440 (24 часа).")
    filters = dict(filters)
    if not any(k in filters for k in ("sinceMs", "untilMs")):
        end = int(time.time() * 1000) if now_ms is None else now_ms
        filters.update(sinceMs=end - int(minutes * 60000), untilMs=end)
    for key in ("sinceMs", "untilMs", "beforeTsMs"):
        if key in filters and (type(filters[key]) is not int or not 0 <= filters[key] <= 2**53 - 1):
            raise LogsError(f"{key} должен быть неотрицательным целым числом миллисекунд Unix.")
    if not all(k in filters for k in ("sinceMs", "untilMs")):
        raise LogsError("Укажите обе границы: sinceMs и untilMs.")
    if not 0 < filters["untilMs"] - filters["sinceMs"] <= 86400000:
        raise LogsError("Окно sinceMs/untilMs должно быть положительным и не больше 24 часов.")
    if filters.get("orderDirection", "desc") not in ("asc", "desc"):
        raise LogsError("orderDirection: asc или desc.")
    if filters.get("orderDirection") == "asc" and "beforeTsMs" in filters:
        raise LogsError("beforeTsMs работает только для desc; для asc сузьте окно.")
    body = {"filters": filters}
    if action == "list":
        body["limit"] = limit
    return body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, type=account_host, help="Домен аккаунта исполнения")
    parser.add_argument("--action", choices=ACTIONS, default="list")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--filters", default="{}", help="JSON-объект фильтров")
    group.add_argument("--filters-file", type=Path, help="Файл JSON с фильтрами")
    parser.add_argument("--minutes", type=float, default=15, help="Последние N минут, если нет явных границ")
    parser.add_argument("--limit", type=int, default=50, help="Число строк: 1–500")
    parser.add_argument("--no-browser", action="store_true", help="Только напечатать ссылку подтверждения")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--login", action="store_true", help="Запросить подтверждение доступа на 2, 6 или 12 часов")
    auth.add_argument("--auth-status", action="store_true", help="Локальный статус; без запроса к серверу и вывода ключа")
    auth.add_argument("--logout", action="store_true", help="Отозвать доступ на сервере и удалить локальный ключ")
    parser.add_argument("--output", type=Path, help="Новый файл полного JSON-ответа, без перезаписи")
    args = parser.parse_args()
    try:
        if args.login:
            print(json.dumps(login_grant(args.account, not args.no_browser), ensure_ascii=False))
            return
        if args.auth_status:
            print(json.dumps(grant_status(saved_grant(args.account)), ensure_ascii=False))
            return
        if args.logout:
            print(json.dumps(logout_grant(args.account, saved_grant(args.account)), ensure_ascii=False))
            return
        filters = json.loads(args.filters_file.read_text(encoding="utf-8") if args.filters_file else args.filters)
        body = make_body(args.action, filters, args.minutes, args.limit)
        if args.output and args.output.expanduser().exists():
            raise LogsError("Файл --output уже существует; выберите новый путь.")
        record = saved_grant(args.account)
        if record["state"] != "active":
            raise LogsError("Нет активного доступа. Запустите --login для этого аккаунта.")
        result = fetch_grant_logs(args.account, record, args.action, body)
        output_path = private_write(args.output, json.dumps(result, ensure_ascii=False) + "\n") if args.output else None
        print(json.dumps(compact_result(result, args.account, args.action, body, output_path), ensure_ascii=False))
    except (LogsError, OSError, ValueError, argparse.ArgumentTypeError) as error:
        print(json.dumps({"success": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

"""Offline behavioral checks. All hosts, keys and responses below are synthetic."""

import io
import json
from pathlib import Path
import tempfile
import urllib.error
from unittest.mock import patch

import read_logs as logs


def fails(call, expected=logs.LogsError):
    try:
        call()
    except expected as error:
        return error
    raise AssertionError("expected a failure")


class Transport:
    def __init__(self):
        self.responses = []
        self.requests = []

    def open(self, request, timeout):
        assert timeout == 45
        self.requests.append(request)
        assert request.get_header("Cookie") is None
        assert request.full_url.startswith("https://account.example/app/dev/")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(response if isinstance(response, bytes) else json.dumps(response).encode())


def check():
    host, key, secret, now = "account.example", "a" * 32, "b" * 64, 1800000000
    transport = Transport()
    requested = {"success": True, "grantKey": key, "userCode": "1234ABCD",
                 "verificationUrl": "https://untrusted.example/"}
    approved = {"success": True, "grantKey": key, "endpoint": logs.grant_endpoint(key),
                "expiresAt": logs.datetime.fromtimestamp(now + 43200, logs.timezone.utc).isoformat()}
    page = {"success": True, "rows": [{"msg": "Ошибка", "retry_count": 0}], "hasMore": False}

    def cli(*args, success=True):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(logs.sys, "argv", ["read_logs.py", "--account", host, *args]), \
                patch.object(logs.sys, "stdout", out), patch.object(logs.sys, "stderr", err):
            if success:
                logs.main()
            else:
                assert fails(logs.main, SystemExit).code == 1
        assert secret not in out.getvalue() and secret not in err.getvalue()
        # Login also writes its human approval prompt to stderr before an error.
        payload = out.getvalue() if success else err.getvalue().splitlines()[-1]
        return json.loads(payload), err.getvalue()

    with tempfile.TemporaryDirectory() as tmp, \
            patch.object(logs.Path, "home", return_value=Path(tmp)), \
            patch.object(logs.time, "time", return_value=now), \
            patch.object(logs.time, "sleep"), \
            patch.object(logs.secrets, "token_hex", return_value=secret), \
            patch.object(logs.webbrowser, "open", side_effect=AssertionError("unexpected browser")), \
            patch.object(logs.urllib.request, "build_opener", return_value=transport):
        assert cli("--auth-status")[0]["state"] == "missing"
        assert not transport.requests
        transport.responses = [requested, {"state": "pending"}, approved]
        status, prompt = cli("--login", "--no-browser")
        assert status["state"] == "active" and "1234-ABCD" in prompt
        assert "https://account.example/app/dev/log-access?grantKey=" + key in prompt
        assert "untrusted.example" not in prompt
        request = transport.requests[0]
        assert request.get_method() == "POST"
        assert request.get_header("X-chatium-logs-key") is None
        assert json.loads(request.data) == {"keyHash": logs.hashlib.sha256(secret.encode()).hexdigest()}
        for request in transport.requests[1:]:
            assert request.get_header("X-chatium-logs-key") == secret
            assert secret not in request.full_url and secret not in request.data.decode()
        path = logs.grant_path(host)
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        record = logs.saved_grant(host)
        assert record["accessKey"] == secret
        active = record.copy()
        logs.write_grant_record(path, active)
        transport.responses = [page]
        result, _ = cli("--filters", '{"onlyErrors":true}', "--minutes", "60")
        request = transport.requests[-1]
        assert request.full_url == "https://account.example/app/dev/agent-logs~" + key
        assert result["rows"][0]["retry_count"] == 0
        assert json.loads(request.data) == {"action": "list", "limit": 50, "filters": {
            "onlyErrors": True, "sinceMs": now * 1000 - 3600000, "untilMs": now * 1000}}
        transport.responses = [{"success": True, "total": 7, "byLevel": {"info": 7}}]
        assert cli("--action", "count")[0]["total"] == 7
        assert json.loads(transport.requests[-1].data)["action"] == "count"

        # Remote failures are errors, never empty results or secret-bearing output.
        for response in (b"<html>Login</html>", {"success": False, "reason": secret},
                         {"success": True}, urllib.error.HTTPError(request.full_url, 403, secret, {}, None),
                         urllib.error.URLError(secret)):
            transport.responses = [response]
            assert cli(success=False)[0]["success"] is False

        full = {"success": True, "rows": [{"msg": "x" * 4000} for _ in range(50)],
                "hasMore": True, "nextCursor": {"ts64": "2024-01-01 00:00:00.000"}}
        output = Path(tmp) / "response.json"
        transport.responses = [full]
        result, _ = cli("--output", str(output))
        assert json.loads(output.read_text(encoding="utf-8")) == full
        assert output.stat().st_mode & 0o777 == 0o600
        assert result["client"]["outputTruncated"] and result["hasMore"]
        assert result["client"]["rowsShown"] < 50
        assert len(json.dumps(result, ensure_ascii=False)) <= logs.MAX_OUTPUT_CHARS
        count = len(transport.requests)
        cli("--output", str(output), success=False)
        assert len(transport.requests) == count
        fails(lambda: logs.private_write(output, "overwrite"), FileExistsError)
        link = Path(tmp) / "symlink.json"
        link.symlink_to(output)
        fails(lambda: logs.private_write(link, "overwrite"), FileExistsError)
        assert json.loads(output.read_text(encoding="utf-8")) == full

        # Local status doesn't call the server; logout must preserve retry ability.
        assert cli("--auth-status")[0]["state"] == "active"
        assert len(transport.requests) == count
        transport.responses = [urllib.error.URLError("offline")]
        cli("--logout", success=False)
        assert secret in path.read_text()
        transport.responses = [approved, {"success": True}]
        cli("--logout")
        assert transport.requests[-1].full_url.endswith("/revoke")
        assert json.loads(transport.requests[-1].data) == {}
        assert secret not in path.read_text() and logs.saved_grant(host)["state"] == "revoked"
        logs.write_grant_record(path, active)
        transport.responses = [{"success": False, "state": "invalid_request"}]
        cli("--logout")
        assert transport.requests[-1].full_url.endswith("~status")
        assert secret not in path.read_text()

        logs.write_grant_record(path, active)
        with patch.object(logs.time, "time", return_value=now + 43200), \
                patch.dict(logs.os.environ, {"CHATIUM_API_TOKEN": "unused-synthetic-token"}):
            assert cli("--auth-status")[0]["state"] == "expired"
            count = len(transport.requests)
            cli(success=False)
            assert len(transport.requests) == count and secret not in path.read_text()
        for change in ({"account": "other.example"}, {"endpoint": "https://untrusted.example/"},
                       {"expiresAt": now + 43201}):
            logs.write_grant_record(path, {**active, **change})
            fails(lambda: logs.saved_grant(host))
        logs.write_grant_record(path, active)
        path.chmod(0o644)
        fails(lambda: logs.saved_grant(host))
        path.unlink()
        transport.responses = [requested, {"success": False, "state": "denied"}]
        cli("--login", "--no-browser", success=False)
        assert not path.exists()
        transport.responses = [requested, {**approved, "endpoint": "https://untrusted.example/"}]
        cli("--login", "--no-browser", success=False)
        assert not path.exists()
        with patch.object(logs.time, "monotonic", side_effect=[0, 301]):
            transport.responses = [requested]
            cli("--login", "--no-browser", success=False)
        assert not path.exists()
        assert not transport.responses

        # A server that keeps returning pending cannot keep the loop alive.
        elapsed = 0

        def advance(seconds):
            nonlocal elapsed
            elapsed += seconds

        with patch.object(logs.time, "monotonic", side_effect=lambda: elapsed), \
                patch.object(logs.time, "sleep", side_effect=advance):
            count = len(transport.requests)
            transport.responses = [requested] + [{"state": "pending"}] * 60
            cli("--login", "--no-browser", success=False)
            assert elapsed == 300 and len(transport.requests) - count == 61
        assert not path.exists() and not transport.responses

    body = logs.make_body("list", {"search": "Ошибка"}, now_ms=1000000)
    assert body["filters"]["sinceMs"] == 100000 and body["limit"] == 50
    history = {"sinceMs": 1, "untilMs": 100, "traceId": "example-trace"}
    assert logs.make_body("count", history)["filters"] == history
    for filters in ([], {"filters": {}}, {"sinceMs": 1}, {"sinceMs": 100, "untilMs": 1},
                    {"sinceMs": 0, "untilMs": 86400001}, {"sinceMs": True, "untilMs": 10},
                    {"sinceMs": 1.5, "untilMs": 10}, {"orderDirection": "asc", "beforeTsMs": 1}):
        fails(lambda: logs.make_body("list", filters))
    for minutes in (0, 1441, float("nan")):
        fails(lambda: logs.make_body("list", {}, minutes=minutes))
    fails(lambda: logs.make_body("export", {}))
    for value in (None, "", "z" * 64, secret + "\r\nCookie: injected", [secret]):
        fails(lambda: logs.validate_access_key(value))
    for value in ("account.example/path", "account.example@untrusted.example", "http://account.example"):
        fails(lambda: logs.account_host(value), logs.argparse.ArgumentTypeError)
    assert logs.account_host("https://ACCOUNT.example/") == host
    assert logs.NoRedirect().redirect_request(None, None, 302, "", {}, "https://untrusted.example") is None
    print("OK: approval, bounded polling, HTTPS header, list/count, bounded output, private files, revocation and expiry")


if __name__ == "__main__":
    # Fail closed if a new code path accidentally tries to use real network I/O.
    with patch.object(logs.urllib.request, "build_opener", side_effect=AssertionError("unexpected network")):
        check()

"""The Python client against a stand-in for the API on this machine."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
import threading
import time
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zerocaptcha import (  # noqa: E402
    DEFAULT_BASE_URL,
    TaskFailedError,
    WaitTimeoutError,
    ZeroCaptcha,
    ZeroCaptchaError,
    verify_signature,
)

KEY = "zc_live_StandInKeyForTheSdkTests0123456789a"
TASK = {"website_url": "https://shop.example.com/login", "website_key": "0x4AAAAAAAB1cD2eF3gH4iJ5"}


class StandIn:
    """Answers as the REST API does, from a script of statuses per task, and records requests."""

    def __init__(self) -> None:
        self.seen: List[Dict[str, Any]] = []
        self.script: Dict[str, List[str]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.by_key: Dict[str, str] = {}
        self.refusals: List[Dict[str, Any]] = []
        #: How long each read of a task takes to answer, in seconds.
        self.read_delay = 0.0
        #: How many task creations, made in full, to answer with a body cut short.
        self.cut_bodies = 0
        self.next = 0
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - the standard library's name
                stand_in.handle(self)

            def do_POST(self) -> None:  # noqa: N802 - the standard library's name
                stand_in.handle(self)

        class Server(ThreadingHTTPServer):
            def handle_error(self, *_: Any) -> None:
                # A client that gave up, as a wait that ran out does, is no error of the stand-in's.
                pass

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def handle(self, request: BaseHTTPRequestHandler) -> None:
        length = int(request.headers.get("Content-Length") or 0)
        text = request.rfile.read(length).decode("utf-8") if length else ""
        self.seen.append(
            {
                "method": request.command,
                "path": request.path,
                "headers": dict(request.headers),
                "body": json.loads(text) if text else None,
            }
        )

        def send(status: int, body: Any, headers: Optional[Dict[str, str]] = None) -> None:
            data = json.dumps(body).encode("utf-8")
            request.send_response(status)
            kind = "application/problem+json" if status >= 400 else "application/json"
            request.send_header("Content-Type", kind)
            request.send_header("Content-Length", str(len(data)))
            for name, value in (headers or {}).items():
                request.send_header(name, value)
            request.end_headers()
            request.wfile.write(data)

        def refuse(status: int, code: str, headers: Optional[Dict[str, str]] = None) -> None:
            problem = {
                "type": "about:blank",
                "title": code,
                "status": status,
                "code": code,
                "detail": f"Refused: {code}.",
                "request_id": "req-1",
            }
            send(status, problem, headers)

        if request.headers.get("Authorization") != f"Bearer {KEY}":
            refuse(401, "unauthorized")
            return
        if self.refusals:
            refusal = self.refusals.pop(0)
            refuse(refusal["status"], refusal["code"], refusal.get("headers"))
            return
        if request.command == "POST" and request.path == "/v1/tasks":
            key = request.headers.get("Idempotency-Key")
            if key in self.by_key:
                send(201, self.tasks[self.by_key[key]])
                return
            body = json.loads(text)
            self.next += 1
            task_id = f"0192f3a4-7b1c-7d2e-9f10-00000000000{self.next}"
            task = {
                "id": task_id,
                "type": body["type"],
                "status": "queued",
                "websiteURL": body["websiteURL"],
                "websiteKey": body.get("websiteKey"),
                "price": "0.000800",
                "held": "0.000800",
                "cost": "0.000000",
                "createdAt": "2026-09-30T10:00:00Z",
            }
            self.tasks[task_id] = task
            if key:
                self.by_key[key] = task_id
            if self.cut_bodies > 0:
                # The task is made; its answer stops halfway, and the connection drops.
                self.cut_bodies -= 1
                whole = json.dumps(task).encode("utf-8")
                request.send_response(201)
                request.send_header("Content-Type", "application/json")
                request.send_header("Content-Length", str(len(whole)))
                request.end_headers()
                request.wfile.write(whole[:20])
                request.wfile.flush()
                request.close_connection = True
                return
            send(201, task, {"Location": f"/v1/tasks/{task_id}"})
            return
        read = re.match(r"^/v1/tasks/([^/]+)$", request.path)
        if request.command == "GET" and read:
            if self.read_delay:
                time.sleep(self.read_delay)
            task = self.tasks.get(read.group(1))
            if task is None:
                refuse(404, "not_found")
                return
            script = self.script.get(task["id"], ["succeeded"])
            status = script.pop(0) if len(script) > 1 else script[0]
            ended: Dict[str, Any] = {}
            if status == "succeeded" and task["type"] == "CloudflareChallengeTask":
                ended = {
                    "cost": "0.001200",
                    "held": "0.000000",
                    "tokenExpiresAt": "2026-09-30T10:30:00Z",
                    "solution": {
                        "token": "stand-in-clearance",
                        "userAgent": "Mozilla/5.0 (stand-in)",
                        "cookie": {"name": "cf_clearance", "value": "stand-in-clearance", "expiresAt": None},
                    },
                }
            elif status == "succeeded":
                ended = {"cost": "0.000800", "held": "0.000000", "solution": {"token": "0.stand-in-token"}}
            elif status == "failed":
                ended = {
                    "held": "0.000000",
                    "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                    "errorDescription": "The task could not be solved. Nothing was charged.",
                }
            send(200, {**task, "status": status, **ended})
            return
        if request.command == "GET" and request.path == "/v1/balance":
            send(200, {"available": "14.100000", "held": "0.000800", "currency": "USD"})
            return
        refuse(404, "not_found")


class ClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.api = StandIn()
        self.client = ZeroCaptcha(api_key=KEY, base_url=self.api.url)

    def tearDown(self) -> None:
        self.api.stop()

    def test_solve_creates_a_proxyless_task_polls_it_and_returns_its_token(self) -> None:
        self.api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = ["queued", "running", "succeeded"]
        self.assertEqual(self.client.solve(**TASK, interval=0.01), "0.stand-in-token")
        create, *reads = self.api.seen
        self.assertEqual((create["method"], create["path"]), ("POST", "/v1/tasks"))
        self.assertEqual(
            create["body"],
            {
                "type": "TurnstileTaskProxyless",
                "websiteURL": TASK["website_url"],
                "websiteKey": TASK["website_key"],
            },
        )
        self.assertRegex(create["headers"]["Idempotency-Key"], r"^[0-9a-f-]{36}$")
        self.assertEqual(len(reads), 3)

    def test_solve_challenge_goes_through_the_proxy_and_returns_the_clearance(self) -> None:
        self.api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = ["running", "succeeded"]
        clearance = self.client.solve_challenge(
            "https://shop.example.com/", "http://user:pass@proxy.example.net:8080", interval=0.01
        )
        self.assertEqual(
            clearance,
            {
                "cf_clearance": "stand-in-clearance",
                "user_agent": "Mozilla/5.0 (stand-in)",
                "token_expires_at": "2026-09-30T10:30:00Z",
            },
        )
        self.assertEqual(
            self.api.seen[0]["body"],
            {
                "type": "CloudflareChallengeTask",
                "websiteURL": "https://shop.example.com/",
                "proxy": "http://user:pass@proxy.example.net:8080",
            },
        )
        self.assertRegex(self.api.seen[0]["headers"]["Idempotency-Key"], r"^[0-9a-f-]{36}$")

    def test_a_challenge_that_fails_raises_task_failed_error(self) -> None:
        self.api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = ["failed"]
        with self.assertRaises(TaskFailedError) as raised:
            self.client.solve_challenge(
                "https://shop.example.com/", "http://proxy.example.net:8080", interval=0.01
            )
        self.assertEqual(raised.exception.code, "ERROR_CAPTCHA_UNSOLVABLE")

    def test_a_proxy_makes_a_proxy_task_and_the_callback_url_is_sent(self) -> None:
        self.client.create_task(
            **TASK,
            proxy="http://user:pass@proxy.example.net:8080",
            callback_url="https://hooks.example.com/zc",
            idempotency_key="order-1234",
        )
        sent = self.api.seen[0]
        self.assertEqual(sent["body"]["type"], "TurnstileTask")
        self.assertEqual(sent["body"]["callbackUrl"], "https://hooks.example.com/zc")
        self.assertEqual(sent["headers"]["Idempotency-Key"], "order-1234")

    def test_a_task_that_fails_raises_task_failed_error_with_its_code(self) -> None:
        self.api.script["0192f3a4-7b1c-7d2e-9f10-000000000001"] = ["running", "failed"]
        with self.assertRaises(TaskFailedError) as raised:
            self.client.solve(**TASK, interval=0.01)
        self.assertEqual(raised.exception.code, "ERROR_CAPTCHA_UNSOLVABLE")
        self.assertEqual(raised.exception.task["cost"], "0.000000")

    def test_a_wait_that_runs_out_raises_wait_timeout_error(self) -> None:
        created = self.client.create_task(**TASK)
        self.api.script[created["id"]] = ["running"]
        with self.assertRaises(WaitTimeoutError) as raised:
            self.client.wait_for_result(created["id"], timeout=0.05, interval=0.01)
        self.assertEqual(raised.exception.task["status"], "running")

    def test_a_slow_read_does_not_carry_the_wait_past_its_deadline(self) -> None:
        # Regression: the deadline was checked only after a read finished.
        created = self.client.create_task(**TASK)
        self.api.read_delay = 2.0
        started = time.monotonic()
        with self.assertRaises(WaitTimeoutError) as raised:
            self.client.wait_for_result(created["id"], timeout=0.1, interval=0.01)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertIsNone(raised.exception.task)
        self.assertEqual(raised.exception.task_id, created["id"])

    def test_a_retry_after_longer_than_the_time_left_ends_the_wait_at_once(self) -> None:
        created = self.client.create_task(**TASK)
        self.api.script[created["id"]] = ["running"]
        self.api.refusals.append({"status": 429, "code": "rate_limited", "headers": {"Retry-After": "5"}})
        started = time.monotonic()
        with self.assertRaises(WaitTimeoutError):
            self.client.wait_for_result(created["id"], timeout=0.2, interval=0.01)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_an_answer_cut_short_is_retried_with_the_same_key_and_makes_one_task(self) -> None:
        # Regression: a body that could not be read was not retried, so a task the
        # API made surfaced as a raw error, and calling again made a second, paid task.
        self.api.cut_bodies = 1
        self.assertEqual(self.client.create_task(**TASK)["status"], "queued")
        first, second = self.api.seen
        self.assertEqual(first["headers"]["Idempotency-Key"], second["headers"]["Idempotency-Key"])
        self.assertEqual(len(self.api.tasks), 1)

    def test_a_429_is_retried_after_retry_after_with_the_same_key(self) -> None:
        self.api.refusals.append({"status": 429, "code": "rate_limited", "headers": {"Retry-After": "0"}})
        self.assertEqual(self.client.create_task(**TASK)["status"], "queued")
        first, second = self.api.seen
        self.assertEqual(first["headers"]["Idempotency-Key"], second["headers"]["Idempotency-Key"])

    def test_a_refusal_raises_with_the_apis_code_and_request_id(self) -> None:
        self.api.refusals.append({"status": 402, "code": "insufficient_funds"})
        with self.assertRaises(ZeroCaptchaError) as raised:
            self.client.create_task(**TASK)
        error = raised.exception
        self.assertEqual((error.status, error.code, error.request_id), (402, "insufficient_funds", "req-1"))
        self.assertEqual(str(error), "Refused: insufficient_funds.")
        self.assertEqual(len(self.api.seen), 1)

    def test_the_balance_is_read_with_the_key_as_a_bearer_token(self) -> None:
        self.assertEqual(
            self.client.get_balance(),
            {"available": "14.100000", "held": "0.000800", "currency": "USD"},
        )
        self.assertEqual(self.api.seen[0]["headers"]["Authorization"], f"Bearer {KEY}")

    def test_a_key_or_address_that_cannot_be_right_is_refused_at_once(self) -> None:
        with self.assertRaises(ValueError):
            ZeroCaptcha(api_key="sk_test", base_url="https://api.example.com")
        with self.assertRaises(ValueError):
            ZeroCaptcha(api_key=KEY, base_url="api.example.com")

    def test_without_a_base_url_it_calls_the_zerocaptcha_api(self) -> None:
        self.assertEqual(DEFAULT_BASE_URL, "https://api.zerocaptcha.io")
        seen: List[str] = []

        class Answer:
            def __enter__(self) -> "Answer":
                return self

            def __exit__(self, *_: Any) -> None:
                return None

            def read(self) -> bytes:
                return b'{"available": "1.000000", "held": "0.000000", "currency": "USD"}'

        def urlopen(request: Any, timeout: float) -> Answer:
            seen.append(request.full_url)
            return Answer()

        with unittest.mock.patch("urllib.request.urlopen", urlopen):
            for client in (ZeroCaptcha(api_key=KEY), ZeroCaptcha(api_key=KEY, base_url="")):
                client.get_balance()
        self.assertEqual(seen, ["https://api.zerocaptcha.io/v1/balance"] * 2)


class SignatureTest(unittest.TestCase):
    secret = "zcsig_ExampleCallbackSecretShownToOwnersOnly0Z"
    body = '{"id":"0192f3a4","status":"succeeded"}'
    now = 1_790_000_000
    v1 = hmac.new(secret.encode(), f"{now}.{body}".encode(), hashlib.sha256).hexdigest()
    header = f"t={now},v1={v1}"

    def test_a_genuine_call_verifies_as_text_or_bytes(self) -> None:
        self.assertTrue(verify_signature(self.secret, self.header, self.body, now=self.now))
        self.assertTrue(verify_signature(self.secret, self.header, self.body.encode(), now=self.now))

    def test_anything_else_does_not(self) -> None:
        self.assertFalse(verify_signature(self.secret, self.header, self.body + " ", now=self.now))
        self.assertFalse(verify_signature(self.secret + "x", self.header, self.body, now=self.now))
        self.assertFalse(
            verify_signature(self.secret, f"t={self.now + 1},v1={self.v1}", self.body, now=self.now)
        )
        self.assertFalse(verify_signature(self.secret, self.header, self.body, now=self.now + 301))
        self.assertFalse(verify_signature(self.secret, "v1=abc", self.body, now=self.now))
        self.assertFalse(verify_signature(self.secret, None, self.body, now=self.now))


if __name__ == "__main__":
    unittest.main()

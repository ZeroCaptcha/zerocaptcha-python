"""ZeroCaptcha's official Python client.

Create a Cloudflare Turnstile task or a Cloudflare challenge page's task, wait for its result, read
the balance, and check a task callback's signature. It uses the standard library only, and runs on Python 3.9 and later.

    from zerocaptcha import ZeroCaptcha

    client = ZeroCaptcha(api_key=os.environ["ZEROCAPTCHA_KEY"], base_url=os.environ["ZEROCAPTCHA_API"])
    token = client.solve(website_url="https://shop.example.com/login", website_key="0x4AAAAAAAB1cD2eF3gH4iJ5")
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, Mapping, Optional, Union

__all__ = [
    "DEFAULT_BASE_URL",
    "SIGNATURE_HEADER",
    "TaskFailedError",
    "WaitTimeoutError",
    "ZeroCaptcha",
    "ZeroCaptchaError",
    "verify_signature",
]

__version__ = "0.1.0"

#: The API's address when ``base_url`` is not given.
DEFAULT_BASE_URL = "https://api.zerocaptcha.io"

#: The header each callback carries: ``t=<unix seconds>,v1=<hex HMAC-SHA256>``.
SIGNATURE_HEADER = "ZeroCaptcha-Signature"

Task = Dict[str, Any]

_FINAL = {"succeeded", "failed", "expired"}
# Too many requests, or a server busy or away: worth another try after a wait.
_RETRYABLE = {429, 502, 503, 504}
_ATTEMPTS = 3
_SIGNATURE = re.compile(r"^t=(\d+),v1=([0-9a-f]{64})$")


class ZeroCaptchaError(Exception):
    """The API refused a request, or could not serve it."""

    def __init__(
        self,
        message: str,
        status: int,
        code: str,
        request_id: Optional[str] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        #: The HTTP status; 0 when the request never got an answer.
        self.status = status
        #: The API's stable error code, such as ``insufficient_funds`` or ``rate_limited``.
        self.code = code
        #: Quote it when you ask support about this request.
        self.request_id = request_id
        #: How long the API asked you to wait before trying again, in seconds.
        self.retry_after = retry_after


class TaskFailedError(Exception):
    """A task ended without a token: it failed or expired, and nothing was charged."""

    def __init__(self, task: Task) -> None:
        super().__init__(task.get("errorDescription") or f"The task {task.get('status')}.")
        self.task = task
        #: Such as ``ERROR_CAPTCHA_UNSOLVABLE``, from the task's ``errorCode``.
        self.code: str = task.get("errorCode") or (
            "ERROR_TASK_TIMEOUT" if task.get("status") == "expired" else "failed"
        )


class WaitTimeoutError(Exception):
    """The task had not ended when the wait ran out; it may still end, and you can wait again."""

    def __init__(self, task: Optional[Task], task_id: str = "") -> None:
        super().__init__(
            "The wait ran out before the task could be read."
            if task is None
            else f"The task was still {task.get('status')} when the wait ran out."
        )
        #: The task as it was last read; ``None`` when no read finished before the wait ran out.
        self.task = task
        #: The task waited for.
        self.task_id = task_id or (task or {}).get("id", "")


class _DeadlinePassed(Exception):
    """A wait's deadline came during a request: it was cut short, and nothing is retried."""


class ZeroCaptcha:
    """The ZeroCaptcha API, as one account's key sees it.

    :param api_key: your API key, ``zc_live_…``.
    :param base_url: the API's address; ``https://api.zerocaptcha.io`` (``DEFAULT_BASE_URL``)
        when not given or empty.
    :param timeout: how long one request may take, in seconds.
    """

    def __init__(
        self, api_key: str, base_url: Optional[str] = None, timeout: float = 30.0
    ) -> None:
        if not api_key.startswith("zc_live_"):
            raise ValueError("api_key must be a ZeroCaptcha API key, zc_live_….")
        base_url = base_url or DEFAULT_BASE_URL
        if not re.match(r"^https?://", base_url):
            raise ValueError("base_url must be the API's http or https address.")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def create_task(
        self,
        website_url: str,
        website_key: str,
        *,
        type: Optional[str] = None,  # noqa: A002 - the API's own name for it
        action: Optional[str] = None,
        cdata: Optional[str] = None,
        proxy: Optional[str] = None,
        callback_url: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Task:
        """Creates a task; it is charged only if it succeeds.

        Without ``type``, a task is ``TurnstileTaskProxyless``, or ``TurnstileTask`` when
        ``proxy`` is set. Every call sends an ``Idempotency-Key``, one of its own unless you give
        yours, so the client's retries never make a second task.
        """
        body: Dict[str, Any] = {
            "type": type or ("TurnstileTask" if proxy else "TurnstileTaskProxyless"),
            "websiteURL": website_url,
            "websiteKey": website_key,
        }
        for name, value in (
            ("action", action),
            ("cdata", cdata),
            ("proxy", proxy),
            ("callbackUrl", callback_url),
        ):
            if value is not None:
                body[name] = value
        return self._request(
            "POST", "/v1/tasks", body=body, idempotency_key=idempotency_key or str(uuid.uuid4())
        )

    def get_task(self, task_id: str) -> Task:
        """Reads a task; its token is in ``solution`` while it is available."""
        return self._request("GET", f"/v1/tasks/{urllib.parse.quote(task_id, safe='')}")

    def wait_for_result(self, task_id: str, timeout: float = 180.0, interval: float = 2.0) -> Task:
        """Waits for a task to end, and returns it once it succeeded.

        Raises :class:`TaskFailedError` when it failed or expired, and
        :class:`WaitTimeoutError` when the wait ran out first. The wait never runs past
        ``timeout``: each read gets only the time left, and a retry that would wait longer than
        that, such as after a long ``Retry-After``, is not made.
        """
        deadline = time.monotonic() + timeout
        path = f"/v1/tasks/{urllib.parse.quote(task_id, safe='')}"
        last: Optional[Task] = None
        while True:
            try:
                task = self._request("GET", path, deadline=deadline)
            except _DeadlinePassed:
                raise WaitTimeoutError(last, task_id) from None
            last = task
            status = task.get("status")
            if status == "succeeded":
                return task
            if status in _FINAL:
                raise TaskFailedError(task)
            left = deadline - time.monotonic()
            if left <= 0:
                raise WaitTimeoutError(task, task_id)
            time.sleep(min(interval, left))

    def solve(
        self,
        website_url: str,
        website_key: str,
        *,
        timeout: float = 180.0,
        interval: float = 2.0,
        **task: Any,
    ) -> str:
        """Creates a task and waits for it: returns its token.

        Takes :meth:`create_task`'s arguments; raises as :meth:`wait_for_result` does.
        """
        created = self.create_task(website_url, website_key, **task)
        done = self.wait_for_result(created["id"], timeout=timeout, interval=interval)
        solution = done.get("solution") or {}
        token = solution.get("token")
        if not isinstance(token, str):
            raise TaskFailedError(done)
        return token

    def create_challenge_task(
        self,
        website_url: str,
        proxy: str,
        *,
        callback_url: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Task:
        """Creates a Cloudflare challenge page's task, through your proxy; charged only if it succeeds.

        A clearance works only from the address that earned it, so a challenge task always runs
        through ``proxy``, such as ``http://user:pass@proxy.example.net:8080``.
        """
        body: Dict[str, Any] = {
            "type": "CloudflareChallengeTask",
            "websiteURL": website_url,
            "proxy": proxy,
        }
        if callback_url is not None:
            body["callbackUrl"] = callback_url
        return self._request(
            "POST", "/v1/tasks", body=body, idempotency_key=idempotency_key or str(uuid.uuid4())
        )

    def solve_challenge(
        self,
        website_url: str,
        proxy: str,
        *,
        timeout: float = 180.0,
        interval: float = 2.0,
        **task: Any,
    ) -> Dict[str, Any]:
        """Creates a challenge page's task and waits for it: returns its clearance.

        The result has ``cf_clearance`` (the cookie's value), ``user_agent`` (send it with the
        cookie, through the same proxy) and ``token_expires_at``. Raises as
        :meth:`wait_for_result` does.
        """
        created = self.create_challenge_task(website_url, proxy, **task)
        done = self.wait_for_result(created["id"], timeout=timeout, interval=interval)
        solution = done.get("solution") or {}
        cookie = solution.get("cookie") or {}
        user_agent = solution.get("userAgent")
        if not isinstance(cookie.get("value"), str) or not isinstance(user_agent, str):
            raise TaskFailedError(done)
        return {
            "cf_clearance": cookie["value"],
            "user_agent": user_agent,
            "token_expires_at": done.get("tokenExpiresAt"),
        }

    def get_balance(self) -> Dict[str, str]:
        """The account's balance: ``available``, ``held`` and ``currency``, in US dollars."""
        return self._request("GET", "/v1/balance")

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        deadline: Optional[float] = None,
    ) -> Any:
        """Sends one call, trying it up to three times with the same ``Idempotency-Key``.

        It is tried again after no answer, an answer cut short (its body could not be read, or a
        success's did not parse), or a retryable refusal. With a ``deadline`` (``time.monotonic``),
        no attempt and no wait runs past it: :class:`_DeadlinePassed` says it came.
        """

        def left() -> float:
            return float("inf") if deadline is None else deadline - time.monotonic()

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "User-Agent": f"zerocaptcha-python/{__version__}",
        }
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        failure: Optional[ZeroCaptchaError] = None
        for attempt in range(1, _ATTEMPTS + 1):
            remaining = left()
            if remaining <= 0:
                raise _DeadlinePassed()
            request = urllib.request.Request(
                self._base_url + path, data=data, headers=headers, method=method
            )
            try:
                timeout = min(self._timeout, remaining)
                with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                    # The body is part of the answer: one cut short is retried as no answer is,
                    # with the same Idempotency-Key, so a task the API made is returned rather
                    # than made again.
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as error:
                failure = _problem(error)
                in_flight = error.code == 409 and failure.code == "idempotency_key_in_use"
                if not (error.code in _RETRYABLE or in_flight) or attempt == _ATTEMPTS:
                    raise failure from None
                wait = failure.retry_after
            except (OSError, http.client.HTTPException, ValueError) as error:
                if left() <= 0:
                    raise _DeadlinePassed() from None
                failure = ZeroCaptchaError(f"The request got no answer: {error}", 0, "network")
                if attempt == _ATTEMPTS:
                    raise failure from None
                wait = None
            pause = wait if wait is not None else 0.5 * 2**attempt
            if pause >= left():
                raise _DeadlinePassed()
            time.sleep(pause)
        raise failure or ZeroCaptchaError("The request failed.", 0, "network")


def _problem(error: urllib.error.HTTPError) -> ZeroCaptchaError:
    try:
        fields = json.loads(error.read().decode("utf-8"))
    except (ValueError, OSError, http.client.HTTPException):
        fields = {}
    if not isinstance(fields, dict):
        fields = {}
    retry_after = error.headers.get("Retry-After") if error.headers else None
    return ZeroCaptchaError(
        str(fields.get("detail") or fields.get("title") or f"HTTP {error.code}"),
        error.code,
        str(fields.get("code") or f"http_{error.code}"),
        fields.get("request_id") or (error.headers.get("X-Request-Id") if error.headers else None),
        float(retry_after) if retry_after and retry_after.strip().isdigit() else None,
    )


def verify_signature(
    secret: str,
    header: Optional[str],
    body: Union[str, bytes],
    tolerance: int = 300,
    now: Optional[float] = None,
) -> bool:
    """Whether a callback is genuine.

    ``header`` is its ``ZeroCaptcha-Signature``, ``body`` the raw body as it arrived (before any
    parsing), and ``secret`` your callback secret, ``zcsig_…``. The signature is the HMAC-SHA256
    of ``<t>.<body>``; a call older than ``tolerance`` seconds is refused too.
    """
    match = _SIGNATURE.match((header or "").strip())
    if match is None:
        return False
    t, v1 = match.group(1), match.group(2)
    current = time.time() if now is None else now
    if abs(int(current) - int(t)) > tolerance:
        return False
    raw = body.encode("utf-8") if isinstance(body, str) else body
    expected = hmac.new(secret.encode("utf-8"), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)

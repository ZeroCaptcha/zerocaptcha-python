<!-- zc:header (generated from the registry; edit repos/registry.json) -->
# ZeroCaptcha SDK for Python

[![CI](https://github.com/ZeroCaptcha/zerocaptcha-python/actions/workflows/ci.yml/badge.svg)](https://github.com/ZeroCaptcha/zerocaptcha-python/actions/workflows/ci.yml)

The official ZeroCaptcha client for Python: solve Cloudflare Turnstile and Cloudflare challenge pages, wait for results, read the balance and verify callback signatures. Standard library only, Python 3.9+, typed.

[Website](https://zerocaptcha.io/docs/sdks/python) · [Docs](https://zerocaptcha.io/docs) · [Quickstart](https://zerocaptcha.io/docs/quickstart) · [API reference](https://zerocaptcha.io/docs/reference/api) · [Pricing](https://zerocaptcha.io/pricing)
<!-- /zc:header -->

## What it does

`zerocaptcha` is the official ZeroCaptcha client for Python. It creates a Cloudflare Turnstile task or a Cloudflare challenge page's task, waits for the result, reads your balance, and checks a task callback's signature. It uses the standard library only and runs on Python 3.9 and later.

Every task is real and paid from your prepaid balance, and only a task that succeeds is charged.

## Install

```sh
pip install zerocaptcha
```

<!-- zc:include sdks/python/README.md sections="Use|Cloudflare challenge pages|Callbacks" -->
## Use

Give the client your API key (`zc_live_…`, from the dashboard's API keys page) and the API's
address, `https://api.zerocaptcha.io`, which is also its default when the address is empty. Keep
both in your environment rather than in your code.

```python
import os

from zerocaptcha import TaskFailedError, ZeroCaptcha

client = ZeroCaptcha(api_key=os.environ["ZEROCAPTCHA_KEY"], base_url=os.environ["ZEROCAPTCHA_API"])

# Create a task and wait for its token: one call.
try:
    token = client.solve(
        website_url="https://shop.example.com/login",  # the page with the widget
        website_key="0x4AAAAAAAB1cD2eF3gH4iJ5",  # its data-sitekey
        # The widget's data-action and data-cdata, or the action and cData options of
        # turnstile.render(). Leave out any the widget does not set.
        action="login",
        cdata="session-7f3a9c2e",
        # proxy="http://user:pass@proxy.example.net:8080",  # to solve through your own proxy
        # callback_url="https://hooks.example.com/zerocaptcha",  # to be called when it ends
    )
    print(token)
except TaskFailedError as failed:
    print(failed.code)  # such as ERROR_CAPTCHA_UNSOLVABLE; nothing was charged

# Or step by step.
task = client.create_task(
    website_url="https://shop.example.com/login",
    website_key="0x4AAAAAAAB1cD2eF3gH4iJ5",
    action="login",  # the widget's data-action, if it sets one
    cdata="session-7f3a9c2e",  # the widget's data-cdata, if it sets one
    # Your ID for this task, sent as the Idempotency-Key; one is made for you when you give none.
    idempotency_key="login-2026-10-01-0001",
)
done = client.wait_for_result(task["id"], timeout=120)
print(done["solution"]["token"], done["cost"])

# Your balance, in US dollars.
print(client.get_balance()["available"])
```

- Tasks come back as dictionaries, as the API writes them (`id`, `status`, `cost`, `solution`…).
- `proxy="http://user:pass@proxy.example.net:8080"` solves a task through your proxy.
- `create_task` sends an `Idempotency-Key` with every call, one of its own unless you give
  `idempotency_key`, so retrying it never makes a second task.
- A request the API asks you to slow down (429) or cannot serve for a moment (502, 503, 504) is
  tried again after the wait it asks for, three times in all, as is one that got no answer or an
  answer cut short, with the same `Idempotency-Key`. Any other refusal raises
  `ZeroCaptchaError` with the API's `code`, such as `insufficient_funds`, and its `request_id`.
- `wait_for_result` asks every 2 seconds for up to 3 minutes, and never runs past `timeout`: each
  read gets only the time left, and a retry that would wait longer than that is not made. A task
  that fails or expires raises `TaskFailedError`; a wait that runs out raises `WaitTimeoutError`,
  with the task as last read (`task`, `None` if no read finished in time), and you can wait again.

## Cloudflare challenge pages

A challenge page ("Just a moment…") is passed through your proxy, and gives the `cf_clearance`
cookie with the user agent it is bound to. Send both, through the same proxy:

```python
clearance = client.solve_challenge(
    "https://shop.example.com/",
    os.environ["PROXY_URL"],  # such as http://user:pass@proxy.example.net:8080
)
print(clearance["cf_clearance"], clearance["user_agent"])
```

`create_challenge_task` creates the task alone, for `wait_for_result`. A challenge task always
needs a proxy: a clearance works only from the address that earned it.

## Callbacks

A task created with `callback_url` is POSTed to it once it ends, with the task as JSON. Each call
carries `ZeroCaptcha-Signature: t=<unix seconds>,v1=<hex>`, the HMAC-SHA256 of `<t>.<body>` under
your callback secret (`zcsig_…`, on the dashboard's API keys page, for owners). Check it against
the raw body, before you parse it:

```python
from zerocaptcha import verify_signature

if not verify_signature(
    os.environ["ZEROCAPTCHA_CALLBACK_SECRET"],
    request.headers.get("ZeroCaptcha-Signature"),
    request.get_data(),  # the raw bytes, as your framework gives them
):
    abort(401)
```

A call older than five minutes does not verify, so a recorded call cannot be replayed. Answer 2xx
once you have it; any other answer is retried with backoff, eight attempts in all over
roughly 65 to 95 minutes.
<!-- /zc:include -->

## FAQ

**Which API does it call?**
ZeroCaptcha's REST API: `POST /v1/tasks`, `GET /v1/tasks/{id}` and `GET /v1/balance`. The [API reference](https://zerocaptcha.io/docs/reference/api) documents every field and error.

**Does it work with requests, httpx, Scrapy or Selenium?**
Yes: it returns the token or the clearance, and you send it with whatever you already use. See the [Scrapy](https://zerocaptcha.io/blog/scrapy-cloudflare-turnstile) and [httpx](https://zerocaptcha.io/blog/python-httpx-cloudflare-turnstile) tutorials and the [Selenium example](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-selenium).

**Is there an async client?**
Not yet. Run the calls in a thread (`asyncio.to_thread`) from async code.

**What does a solve cost?**
The [pricing page](https://zerocaptcha.io/pricing) lists the price per 1,000 solved tasks. Only a task that succeeds is charged.

## Develop

```sh
python -m unittest discover -s tests   # against a stand-in API on your machine
```

This repository is a mirror of the SDK as it is developed in ZeroCaptcha's main repository, copied here on every release. Issues and pull requests are welcome here; an accepted change is made upstream and comes back with the next release.

<!-- zc:footer (generated from the registry) -->
## More from ZeroCaptcha

- The website: [ZeroCaptcha](https://zerocaptcha.io), the [docs](https://zerocaptcha.io/docs), the [guides](https://zerocaptcha.io/guides), the [blog](https://zerocaptcha.io/blog) and the [status page](https://zerocaptcha.io/status)
- Start here: [zerocaptcha](https://github.com/ZeroCaptcha/zerocaptcha), [cloudflare-turnstile-solver](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver), [cloudflare-challenge-solver](https://github.com/ZeroCaptcha/cloudflare-challenge-solver)
- Examples by language: [cloudflare-turnstile-solver-python](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-python), [cloudflare-turnstile-solver-nodejs](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-nodejs), [cloudflare-turnstile-solver-go](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-go), [cloudflare-turnstile-solver-php](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-php), [cloudflare-turnstile-solver-java](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-java), [cloudflare-turnstile-solver-csharp](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-csharp), [cloudflare-turnstile-solver-rust](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-rust)
- Browser automation: [cloudflare-turnstile-solver-playwright](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-playwright), [cloudflare-turnstile-solver-puppeteer](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-puppeteer), [cloudflare-turnstile-solver-selenium](https://github.com/ZeroCaptcha/cloudflare-turnstile-solver-selenium)
- SDKs, MCP server and migration: [zerocaptcha-js](https://github.com/ZeroCaptcha/zerocaptcha-js), **zerocaptcha-python**, [zerocaptcha-go](https://github.com/ZeroCaptcha/zerocaptcha-go), [zerocaptcha-mcp](https://github.com/ZeroCaptcha/zerocaptcha-mcp), [createtask-api-migration](https://github.com/ZeroCaptcha/createtask-api-migration)
- Lists: [awesome-cloudflare-turnstile](https://github.com/ZeroCaptcha/awesome-cloudflare-turnstile)

## Licence

MIT: see [LICENSE](LICENSE).

## Disclaimer

ZeroCaptcha is an independent service, not affiliated with or endorsed by Cloudflare. Cloudflare and Turnstile are trademarks of Cloudflare, Inc. Use ZeroCaptcha only on sites you own or are allowed to automate, as the [Acceptable Use Policy](https://zerocaptcha.io/legal/acceptable-use) says; any site owner can [opt out](https://zerocaptcha.io/opt-out).
<!-- /zc:footer -->

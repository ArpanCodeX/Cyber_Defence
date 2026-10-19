#!/usr/bin/env python3
"""Bounded load test for the local authorized demo server.

Use only against systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_REQUESTS = 200
MAX_WORKERS = 10
DEFAULT_URL = "http://127.0.0.1:8080/"


def send_request(url: str, timeout: float) -> tuple[int | None, str]:
    request = Request(
        url,
        headers={
            "User-Agent": "authorized-local-load-test/1.0",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            response.read(256)
            return response.status, ""
    except HTTPError as error:
        return error.code, ""
    except (URLError, TimeoutError, OSError) as error:
        return None, str(error)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded local demo load test")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    if not args.url.startswith(("http://127.0.0.1", "http://localhost")):
        parser.error("Safety check: --url must target localhost or 127.0.0.1")

    if not 1 <= args.requests <= MAX_REQUESTS:
        parser.error(f"--requests must be between 1 and {MAX_REQUESTS}")

    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}")

    if not 0.1 <= args.timeout <= 10:
        parser.error("--timeout must be between 0.1 and 10 seconds")

    print(f"Sending {args.requests} requests to {args.url}")
    print(f"Concurrency: {args.workers}")
    print("This is a bounded local test, not a DoS attack.")

    counts: dict[str, int] = {}
    started = time.monotonic()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(send_request, args.url, args.timeout)
            for _ in range(args.requests)
        ]

        for future in as_completed(futures):
            status, error = future.result()
            key = str(status) if status is not None else f"error: {error}"
            counts[key] = counts.get(key, 0) + 1

    elapsed = time.monotonic() - started

    print(f"Completed in {elapsed:.2f}s")
    for result, count in sorted(counts.items()):
        print(f"{result}: {count}")

    if any(code in counts for code in ("403", "429")):
        print("The security controls returned blocking/rate-limit responses.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _load_runtime():
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from opencompliance.verification_api import (  # pylint: disable=import-error
        DEFAULT_VERIFY_API_HOST,
        DEFAULT_VERIFY_API_PORT,
        serve_verify_api,
    )

    return root, DEFAULT_VERIFY_API_HOST, DEFAULT_VERIFY_API_PORT, serve_verify_api


def main() -> int:
    root, default_host, default_port, serve = _load_runtime()
    parser = argparse.ArgumentParser(description="Serve the local OpenCompliance Verify HTTP API.")
    parser.add_argument("--host", default=default_host, help="Host to bind. Defaults to 127.0.0.1.")
    parser.add_argument("--port", type=int, default=default_port, help="Port to bind. Defaults to 8788.")
    args = parser.parse_args()
    serve(root, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

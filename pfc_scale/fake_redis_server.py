from __future__ import annotations

import argparse

from fakeredis import TcpFakeServer


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP fake redis server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6379)
    args = parser.parse_args()

    server = TcpFakeServer((args.host, args.port), server_type="redis")
    try:
        server.serve_forever()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()

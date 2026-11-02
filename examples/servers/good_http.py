"""The good demo server, served over Streamable HTTP on 127.0.0.1 (used by the HTTP-check tests)."""
import asyncio
import sys

import good_server

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    asyncio.run(good_server.mcp.run_streamable_http_async(host="127.0.0.1", port=port))

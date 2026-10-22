"""A fake ACP agent for supervisor tests: no harness, no model.

stdio by default; `tcp <host> <port>` listens instead. Every request is logged to
$FAKE_LOG as `<pid> <method> <sessionId>`. Prompt text "crash" exits 3 mid-turn,
"permission" asks the client for permission before finishing.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

SID = os.environ.get("FAKE_SID", "sess-1")


def log(method: str, sid: str = "") -> None:
    path = os.environ.get("FAKE_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{os.getpid()} {method} {sid}\n")


async def serve(reader: asyncio.StreamReader, write) -> None:
    pending: dict = {}
    while True:
        line = await reader.readline()
        if not line:
            return
        msg = json.loads(line)
        if "method" not in msg:
            fut = pending.pop(msg.get("id"), None)
            if fut is not None:
                fut.set_result(msg)
            continue
        asyncio.create_task(handle(msg, write, pending))


async def handle(msg: dict, write, pending: dict) -> None:
    method, id_, params = msg["method"], msg.get("id"), msg.get("params") or {}
    log(method, params.get("sessionId", ""))
    if method == "initialize":
        result = {"protocolVersion": 1, "agentCapabilities": {"loadSession": True}}
    elif method == "session/new":
        result = {"sessionId": SID}
    elif method == "session/load":
        await write({"jsonrpc": "2.0", "method": "session/update",
                     "params": {"sessionId": params["sessionId"], "update": {"sessionUpdate": "history"}}})
        result = None
    elif method == "session/prompt":
        text = "".join(p.get("text", "") for p in params.get("prompt", []))
        if text == "crash":
            os._exit(3)
        if text == "permission":
            fut = asyncio.get_running_loop().create_future()
            pending["perm-1"] = fut
            await write({"jsonrpc": "2.0", "id": "perm-1", "method": "session/request_permission",
                         "params": {"sessionId": params["sessionId"], "options": []}})
            await fut
        await write({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": params["sessionId"],
            "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": f"echo {text}"}},
        }})
        result = {"stopReason": "end_turn"}
    else:
        await write({"jsonrpc": "2.0", "id": id_, "error": {"code": -32601, "message": method}})
        return
    if id_ is not None:
        await write({"jsonrpc": "2.0", "id": id_, "result": result})


async def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "tcp":
        async def on_conn(r, w):
            async def write(obj):
                w.write((json.dumps(obj) + "\n").encode())
                await w.drain()
            await serve(r, write)

        server = await asyncio.start_server(on_conn, sys.argv[2], int(sys.argv[3]))
        async with server:
            await server.serve_forever()
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    lock = asyncio.Lock()

    async def write(obj):
        async with lock:
            sys.stdout.write(json.dumps(obj) + "\n")
            sys.stdout.flush()

    await serve(reader, write)


if __name__ == "__main__":
    asyncio.run(main())

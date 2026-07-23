"""Policy-enforcing MCP stdio gateway.

Prevention is claimed only when the client is configured to use this gateway
as its sole route. Direct server invocation remains a declared bypass risk.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable
from typing import Any, BinaryIO

from watchmyai.core.models import AdapterCapability, ToolRequest
from watchmyai.runtime import RuntimeResult, WatchMyAIRuntime
from watchmyai.schema.event import canonical_hash

EmitFn = Callable[[dict[str, Any]], Any]
ADAPTER_ID = "generic_mcp_gateway"
CAPABILITY = AdapterCapability(
    adapter_id=ADAPTER_ID,
    adapter_version="1.0.0",
    supports_pre_execution=True,
    supports_post_execution=True,
    supports_blocking=True,
    supports_argument_redaction=True,
    supports_result_redaction=True,
    supports_hashing=True,
    supports_telemetry_export=True,
    mediated_tool_classes=frozenset({"mcp"}),
    source="gateway_route",
)


class MCPSessionParser:
    def __init__(self, runtime: WatchMyAIRuntime, gateway_name: str, server_fingerprint: str):
        self.runtime = runtime
        self.gateway_name = gateway_name
        self.server_fingerprint = server_fingerprint
        self.session_id = "mcp-" + uuid.uuid4().hex
        self.client_name = "unknown"
        self.pending: dict[Any, RuntimeResult] = {}

    def authorize_start(self) -> RuntimeResult:
        return self.runtime.process(
            ToolRequest(
                adapter_id=ADAPTER_ID,
                agent_id="mcp_client",
                session_id=self.session_id,
                task_id="task-" + self.session_id,
                tool_name="mcp.connect",
                tool_class="mcp",
                operation="connect",
                mcp_server_id=self.gateway_name,
                mcp_server_fingerprint=self.server_fingerprint,
            )
        )

    def on_client_line(self, raw: bytes) -> tuple[bool, bytes | None]:
        message = self._parse(raw)
        if message is None:
            return False, self._error(None, "invalid JSON-RPC message")
        method = message.get("method")
        params = message.get("params") or {}
        message_id = message.get("id")
        if method == "initialize" and isinstance(params, dict):
            client = params.get("clientInfo") or {}
            if isinstance(client, dict) and client.get("name"):
                self.client_name = str(client["name"])
            return True, None
        if method != "tools/call":
            return True, None
        if not isinstance(params, dict):
            return False, self._error(message_id, "invalid tools/call params")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return False, self._error(message_id, "tool arguments must be an object")
        tool = str(params.get("name") or "unknown")
        request = ToolRequest(
            adapter_id=ADAPTER_ID,
            agent_id=self.client_name,
            session_id=self.session_id,
            task_id="task-" + self.session_id,
            tool_name=tool,
            tool_class="mcp",
            operation="call",
            arguments=arguments,
            mcp_server_id=self.gateway_name,
            mcp_server_fingerprint=self.server_fingerprint,
            request_id="req-" + canonical_hash([self.session_id, message_id]).removeprefix("sha256:")[:32],
            action_id="act-" + canonical_hash([self.session_id, message_id]).removeprefix("sha256:")[:32],
        )
        result = self.runtime.process(request)
        if not result.enforcement.permitted:
            return False, self._error(message_id, f"WatchMyAI blocked MCP call: {result.enforcement.reason}")
        if message_id is not None:
            self.pending[message_id] = result
        return True, None

    def on_server_line(self, raw: bytes) -> None:
        message = self._parse(raw)
        if message is None:
            return
        message_id = message.get("id")
        result = self.pending.pop(message_id, None)
        if result is not None:
            failed = "error" in message or bool((message.get("result") or {}).get("isError"))
            self.runtime.record_execution(
                result,
                "failure" if failed else "success",
                result_hash=canonical_hash(message.get("result")) if "result" in message else None,
                error_class="mcp_error" if failed else None,
            )

    @staticmethod
    def _parse(raw: bytes) -> dict[str, Any] | None:
        try:
            value = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _error(message_id: Any, reason: str) -> bytes:
        payload = {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32001, "message": reason}}
        return json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"


def _server_pump(src: BinaryIO, dst: BinaryIO, parser: MCPSessionParser) -> None:
    for raw in iter(src.readline, b""):
        parser.on_server_line(raw)
        try:
            dst.write(raw)
            dst.flush()
        except (BrokenPipeError, ValueError):
            break


def _client_pump(src: BinaryIO, dst: BinaryIO, client_output: BinaryIO, parser: MCPSessionParser) -> None:
    for raw in iter(src.readline, b""):
        try:
            forward, response = parser.on_client_line(raw)
        except Exception as exc:  # strict mediation: parser/runtime failure blocks this request
            forward, response = (
                False,
                parser._error(None, f"WatchMyAI enforcement failure: {type(exc).__name__}"),
            )
        if response:
            client_output.write(response)
            client_output.flush()
        if forward:
            try:
                dst.write(raw)
                dst.flush()
            except (BrokenPipeError, ValueError):
                break


def run_proxy(server_command: list[str], runtime: WatchMyAIRuntime, gateway_name: str = "mcp") -> int:
    if not server_command:
        raise ValueError("no MCP server command given")
    fingerprint = canonical_hash({"gateway_name": gateway_name, "command": server_command})
    parser = MCPSessionParser(runtime, gateway_name, fingerprint)
    start = parser.authorize_start()
    if not start.enforcement.permitted:
        print(f"WatchMyAI refused MCP server start: {start.enforcement.reason}", file=sys.stderr)
        return 126
    server = subprocess.Popen(server_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert server.stdin is not None and server.stdout is not None
    threads = [
        threading.Thread(
            target=_client_pump, args=(sys.stdin.buffer, server.stdin, sys.stdout.buffer, parser), daemon=True
        ),
        threading.Thread(target=_server_pump, args=(server.stdout, sys.stdout.buffer, parser), daemon=True),
    ]
    for thread in threads:
        thread.start()
    threads[0].join()
    try:
        server.stdin.close()
    except OSError:
        pass
    threads[1].join(timeout=5)
    server.wait(timeout=10)
    return server.returncode or 0

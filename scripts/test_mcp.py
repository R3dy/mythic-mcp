#!/usr/bin/env python
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from fastmcp import Client


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_temp_config(
    server_ip: str,
    server_port: int,
    ssl: bool,
    username: str,
    password: str,
    apitoken: str,
    timeout: int,
) -> str:
    cfg = {
        "mythic": {
            "server_ip": server_ip,
            "server_port": server_port,
            "ssl": ssl,
            "username": username,
            "password": password,
            "apitoken": apitoken,
            "timeout": timeout,
            "logging_level": 20,
        },
        "mcp": {
            "name": "mythic_mcp",
            "instructions": "Mythic C2 operator tools for MCP",
        },
    }
    temp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml")
    yaml.safe_dump(cfg, temp)
    temp.close()
    return temp.name


class TestRunner:
    def __init__(self, client: Client, tool_names: List[str], tool_timeout: int) -> None:
        self.client = client
        self.tool_names = set(tool_names)
        self.tool_timeout = tool_timeout
        self.results: List[Dict[str, Any]] = []

    def _resolve(self, name: str) -> str:
        prefixed = f"mythic_{name}"
        if prefixed in self.tool_names:
            return prefixed
        return name

    async def call(self, name: str, args: Dict[str, Any]) -> Tuple[bool, Any, str]:
        tool_name = self._resolve(name)
        try:
            result = await asyncio.wait_for(
                self.client.call_tool(tool_name, args),
                timeout=self.tool_timeout,
            )
            return True, result.content, ""
        except Exception as exc:  # noqa: BLE001
            return False, None, str(exc)

    def record(self, name: str, status: str, detail: str = "") -> None:
        self.results.append(
            {"tool": name, "status": status, "detail": detail.strip()}
        )


def _content_to_data(content: Any) -> Any:
    if not content:
        return None
    item = content[0]
    if isinstance(item, dict):
        item_type = item.get("type")
        if item_type == "json":
            return item.get("json")
        if item_type == "text":
            text = item.get("text", "")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return item
    item_type = getattr(item, "type", None)
    if item_type == "json":
        return getattr(item, "json", None)
    if item_type == "text":
        text = getattr(item, "text", "")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return item


async def run_tests(args: argparse.Namespace) -> int:
    if args.config:
        config_path = args.config
    else:
        config_path = _write_temp_config(
            server_ip=args.server_ip,
            server_port=args.server_port,
            ssl=args.ssl,
            username=args.username,
            password=args.password,
            apitoken=args.apitoken,
            timeout=args.mythic_timeout,
        )

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    python_path = str(repo_root)

    if args.in_memory:
        from mythic_mcp.config import load_config
        from mythic_mcp.server import _build_server

        server = _build_server(load_config(config_path))
        client_ctx = Client(server)
    else:
        client_config = {
            "mcpServers": {
                "mythic": {
                    "command": sys.executable,
                    "args": ["-m", "mythic_mcp", "--config", config_path],
                    "env": {
                        "PYTHONPATH": python_path,
                        "FASTMCP_LOG_LEVEL": "ERROR",
                        "FASTMCP_SHOW_CLI_BANNER": "false",
                    },
                }
            }
        }
        client_ctx = Client(client_config)

    async with client_ctx as client:
        tools = await client.list_tools()
        runner = TestRunner(client, [t.name for t in tools], args.tool_timeout)

        ok, data, err = await runner.call("health_check", {})
        if ok:
            runner.record("health_check", "PASS")
        else:
            runner.record("health_check", "FAIL", err)
            return 1

        callbacks: List[Dict[str, Any]] = []
        ok, data, err = await runner.call("get_all_callbacks", {})
        if ok:
            runner.record("get_all_callbacks", "PASS")
            callbacks = _content_to_data(data) or []
        else:
            runner.record("get_all_callbacks", "FAIL", err)

        ok, _, err = await runner.call("get_active_callbacks", {})
        runner.record("get_active_callbacks", "PASS" if ok else "FAIL", err)

        callback_display_id = None
        if isinstance(callbacks, list) and callbacks:
            callback_display_id = callbacks[0].get("display_id")

        if callback_display_id is not None:
            ok, _, err = await runner.call(
                "get_callback_details", {"callback_display_id": callback_display_id}
            )
            runner.record("get_callback_details", "PASS" if ok else "FAIL", err)
        else:
            runner.record("get_callback_details", "SKIP", "no callbacks")

        ok, _, err = await runner.call("get_all_tasks", {})
        runner.record("get_all_tasks", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call("get_all_task_output", {})
        runner.record("get_all_task_output", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call(
            "subscribe_new_callbacks", {"batch_size": 1, "timeout": 2, "max_items": 1}
        )
        runner.record("subscribe_new_callbacks", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call(
            "subscribe_new_task_output", {"batch_size": 1, "timeout": 2, "max_items": 1}
        )
        runner.record("subscribe_new_task_output", "PASS" if ok else "FAIL", err)

        ok, payloads, err = await runner.call("get_all_payloads", {})
        runner.record("get_all_payloads", "PASS" if ok else "FAIL", err)

        payload_uuid = None
        payload_type_name = None
        payload_list = _content_to_data(payloads)
        if ok and isinstance(payload_list, list) and payload_list:
            payload_uuid = payload_list[0].get("uuid")
            payload = payload_list[0]
            payload_type = payload.get("payloadtype") or {}
            payload_type_name = payload_type.get("name")

        if payload_type_name:
            ok, _, err = await runner.call(
                "get_all_commands_for_payloadtype",
                {"payload_type_name": payload_type_name},
            )
            runner.record(
                "get_all_commands_for_payloadtype", "PASS" if ok else "FAIL", err
            )
        else:
            runner.record("get_all_commands_for_payloadtype", "SKIP", "no payload type")

        if payload_uuid:
            ok, _, err = await runner.call(
                "download_payload", {"payload_uuid": payload_uuid}
            )
            runner.record("download_payload", "PASS" if ok else "FAIL", err)
        else:
            runner.record("download_payload", "SKIP", "no payloads")

        ok, _, err = await runner.call(
            "register_file", {"filename": "mcp_test.txt", "contents_b64": "dGVzdA=="}
        )
        runner.record("register_file", "PASS" if ok else "FAIL", err)

        ok, uploaded, err = await runner.call("get_uploaded_files", {"batch_size": 10})
        runner.record("get_uploaded_files", "PASS" if ok else "FAIL", err)

        ok, downloaded, err = await runner.call("get_downloaded_files", {"batch_size": 10})
        runner.record("get_downloaded_files", "PASS" if ok else "FAIL", err)

        file_uuid = None
        for pool in (uploaded, downloaded):
            pool_data = _content_to_data(pool)
            if not pool_data:
                continue
            for entry in pool_data:
                file_uuid = entry.get("agent_file_id") or entry.get("file_uuid") or entry.get("id")
                if file_uuid:
                    break
            if file_uuid:
                break

        if file_uuid:
            ok, _, err = await runner.call("download_file", {"file_uuid": file_uuid})
            runner.record("download_file", "PASS" if ok else "FAIL", err)
        else:
            runner.record("download_file", "SKIP", "no files available")

        ok, _, err = await runner.call("get_screenshots", {})
        runner.record("get_screenshots", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call("get_filebrowser", {"host": None, "batch_size": 50})
        runner.record("get_filebrowser", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call("get_processes", {"host": None, "batch_size": 50})
        runner.record("get_processes", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call(
            "subscribe_new_filebrowser", {"host": None, "batch_size": 10, "timeout": 2}
        )
        runner.record("subscribe_new_filebrowser", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call(
            "subscribe_new_processes", {"host": None, "batch_size": 10, "timeout": 2}
        )
        runner.record("subscribe_new_processes", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call("get_unique_compromised_hosts", {})
        runner.record("get_unique_compromised_hosts", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call("get_unique_compromised_ips", {})
        runner.record("get_unique_compromised_ips", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call("get_unique_compromised_accounts", {})
        runner.record("get_unique_compromised_accounts", "PASS" if ok else "FAIL", err)

        ok, _, err = await runner.call("get_all_tag_types", {})
        runner.record("get_all_tag_types", "PASS" if ok else "FAIL", err)

        query = """
        query GetOperations {
            operation { id name complete }
        }
        """
        ok, _, err = await runner.call("execute_custom_query", {"query": query, "variables": {}})
        runner.record("execute_custom_query", "PASS" if ok else "FAIL", err)

        if callback_display_id is not None:
            subscription = """
            subscription MonitorCallback($callback_id: Int!, $now: timestamp!) {
                task_stream(
                    where: {callback: {display_id: {_eq: $callback_id}}}
                    cursor: {initial_value: {timestamp: $now}}
                    batch_size: 1
                ) {
                    id
                    display_id
                }
            }
            """
            ok, _, err = await runner.call(
                "subscribe_custom_query",
                {
                    "query": subscription,
                    "variables": {"callback_id": callback_display_id, "now": _utc_iso()},
                    "timeout": 2,
                    "max_items": 1,
                },
            )
            runner.record("subscribe_custom_query", "PASS" if ok else "FAIL", err)
        else:
            runner.record("subscribe_custom_query", "SKIP", "no callbacks")

        if args.allow_tasking and callback_display_id is not None:
            ok, task, err = await runner.call(
                "issue_task",
                {
                    "callback_display_id": callback_display_id,
                    "command_name": args.task_command,
                    "parameters": args.task_parameters,
                    "wait_for_complete": False,
                    "timeout": 30,
                },
            )
            runner.record("issue_task", "PASS" if ok else "FAIL", err)
            task_display_id = None
            task_data = _content_to_data(task)
            if ok and isinstance(task_data, dict):
                task_display_id = task_data.get("display_id")
            if task_display_id is not None:
                ok, _, err = await runner.call(
                    "wait_for_task_output",
                    {"task_display_id": task_display_id, "timeout": 10},
                )
                runner.record("wait_for_task_output", "PASS" if ok else "FAIL", err)
            else:
                runner.record("wait_for_task_output", "SKIP", "no task display id")
        elif callback_display_id is None:
            runner.record("issue_task", "SKIP", "no callbacks")
            runner.record("wait_for_task_output", "SKIP", "no callbacks")
        else:
            runner.record("issue_task", "SKIP", "allow_tasking=false")
            runner.record("wait_for_task_output", "SKIP", "allow_tasking=false")

        if args.allow_admin:
            op_name = f"mcp_test_{int(datetime.now().timestamp())}"
            ok, op, err = await runner.call("create_operation", {"operation_name": op_name})
            runner.record("create_operation", "PASS" if ok else "FAIL", err)

            ok, _, err = await runner.call(
                "update_operation", {"operation_name": op_name, "complete": False}
            )
            runner.record("update_operation", "PASS" if ok else "FAIL", err)

            ok, _, err = await runner.call("get_operations", {})
            runner.record("get_operations", "PASS" if ok else "FAIL", err)

            if args.operator_username and args.operator_password and args.operator_email:
                ok, _, err = await runner.call(
                    "create_operator",
                    {
                        "username": args.operator_username,
                        "password": args.operator_password,
                        "email": args.operator_email,
                        "bot": False,
                    },
                )
                runner.record("create_operator", "PASS" if ok else "FAIL", err)

                ok, _, err = await runner.call(
                    "add_operator_to_operation",
                    {
                        "operation_name": op_name,
                        "operator_username": args.operator_username,
                    },
                )
                runner.record("add_operator_to_operation", "PASS" if ok else "FAIL", err)

                ok, _, err = await runner.call(
                    "update_operator_view_mode",
                    {
                        "operation_name": op_name,
                        "operator_username": args.operator_username,
                        "view_mode": "spectator",
                    },
                )
                runner.record("update_operator_view_mode", "PASS" if ok else "FAIL", err)

                ok, _, err = await runner.call(
                    "remove_operator_from_operation",
                    {
                        "operation_name": op_name,
                        "operator_username": args.operator_username,
                    },
                )
                runner.record("remove_operator_from_operation", "PASS" if ok else "FAIL", err)
            else:
                runner.record("create_operator", "SKIP", "operator args not set")
                runner.record("add_operator_to_operation", "SKIP", "operator args not set")
                runner.record("update_operator_view_mode", "SKIP", "operator args not set")
                runner.record("remove_operator_from_operation", "SKIP", "operator args not set")

            ok, _, err = await runner.call(
                "create_credential",
                {
                    "credential": "Password123!",
                    "account": "operator_test",
                    "realm": "LOCAL",
                    "credential_type": "plaintext",
                    "comment": "mcp test",
                },
            )
            runner.record("create_credential", "PASS" if ok else "FAIL", err)

            if args.c2_profile:
                ok, _, err = await runner.call(
                    "start_stop_c2_profile",
                    {"c2_profile_name": args.c2_profile, "action": "stop"},
                )
                runner.record("start_stop_c2_profile", "PASS" if ok else "FAIL", err)
            else:
                runner.record("start_stop_c2_profile", "SKIP", "c2_profile not set")

            if args.payload_type and args.c2_profile:
                ok, _, err = await runner.call(
                    "create_payload",
                    {
                        "payload_type_name": args.payload_type,
                        "filename": "mcp_test_payload.bin",
                        "operating_system": args.operating_system,
                        "c2_profiles": [
                            {
                                "c2_profile": args.c2_profile,
                                "c2_profile_parameters": args.c2_profile_params or {},
                            }
                        ],
                        "commands": args.payload_commands or [],
                        "build_parameters": args.build_parameters or [],
                        "description": "mcp test payload",
                        "return_on_complete": True,
                        "timeout": 120,
                        "include_all_commands": False,
                    },
                )
                runner.record("create_payload", "PASS" if ok else "FAIL", err)
            else:
                runner.record("create_payload", "SKIP", "payload_type or c2_profile not set")
        else:
            runner.record("create_operation", "SKIP", "allow_admin=false")
            runner.record("update_operation", "SKIP", "allow_admin=false")
            runner.record("get_operations", "SKIP", "allow_admin=false")
            runner.record("create_operator", "SKIP", "allow_admin=false")
            runner.record("add_operator_to_operation", "SKIP", "allow_admin=false")
            runner.record("update_operator_view_mode", "SKIP", "allow_admin=false")
            runner.record("remove_operator_from_operation", "SKIP", "allow_admin=false")
            runner.record("create_credential", "SKIP", "allow_admin=false")
            runner.record("start_stop_c2_profile", "SKIP", "allow_admin=false")
            runner.record("create_payload", "SKIP", "allow_admin=false")

        if args.allow_tasking:
            ok, _, err = await runner.call(
                "issue_task_all_active_callbacks",
                {
                    "command_name": args.task_command,
                    "parameters": args.task_parameters,
                    "payload_type": args.payload_type,
                },
            )
            runner.record("issue_task_all_active_callbacks", "PASS" if ok else "FAIL", err)
        else:
            runner.record("issue_task_all_active_callbacks", "SKIP", "allow_tasking=false")

        report = {
            "timestamp": _utc_iso(),
            "results": runner.results,
        }
        print(json.dumps(report, indent=2))

        failed = [r for r in runner.results if r["status"] == "FAIL"]
        return 1 if failed else 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Test Mythic MCP server tools")
    parser.add_argument("--config", help="Use an existing config.yaml")
    parser.add_argument("--server-ip", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=7443)
    parser.add_argument("--ssl", action="store_true", default=True)
    parser.add_argument("--username", default="mythic_admin")
    parser.add_argument("--password", default="foqKFBZa4wbuFMLDJoSG3XQdmIle3e")
    parser.add_argument("--apitoken", default="")
    parser.add_argument("--mythic-timeout", type=int, default=10)
    parser.add_argument("--tool-timeout", type=int, default=15)
    parser.add_argument("--in-memory", action="store_true")
    parser.add_argument("--allow-tasking", action="store_true")
    parser.add_argument("--allow-admin", action="store_true")
    parser.add_argument("--task-command", default="shell")
    parser.add_argument("--task-parameters", default="whoami")
    parser.add_argument("--c2-profile", default="")
    parser.add_argument("--payload-type", default="")
    parser.add_argument("--operating-system", default="Windows")
    parser.add_argument("--payload-commands", nargs="*", default=[])
    parser.add_argument("--build-parameters", type=json.loads, default="[]")
    parser.add_argument("--c2-profile-params", type=json.loads, default="{}")
    parser.add_argument("--operator-username", default="")
    parser.add_argument("--operator-password", default="")
    parser.add_argument("--operator-email", default="")

    args = parser.parse_args()
    exit_code = asyncio.run(run_tests(args))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

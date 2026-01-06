from __future__ import annotations

import argparse
import asyncio
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP, Context
from mythic import mythic

from .config import AppConfig, load_config


class MythicSession:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._mythic_instance = None

    @property
    def instance(self):
        if self._mythic_instance is None:
            raise RuntimeError("Mythic session not initialized")
        return self._mythic_instance

    async def connect(self) -> None:
        cfg = self._config.mythic
        if cfg.apitoken:
            self._mythic_instance = await mythic.login(
                server_ip=cfg.server_ip,
                server_port=cfg.server_port,
                apitoken=cfg.apitoken,
                ssl=cfg.ssl,
                timeout=cfg.timeout,
                logging_level=cfg.logging_level,
            )
            return

        self._mythic_instance = await mythic.login(
            username=cfg.username,
            password=cfg.password,
            server_ip=cfg.server_ip,
            server_port=cfg.server_port,
            ssl=cfg.ssl,
            timeout=cfg.timeout,
            logging_level=cfg.logging_level,
        )


def _build_server(config: AppConfig) -> FastMCP:
    mcp = FastMCP(config.mcp.name, instructions=config.mcp.instructions)
    session = MythicSession(config)

    async def _ensure_connection(ctx: Optional[Context] = None) -> None:
        try:
            _ = session.instance
        except RuntimeError:
            if ctx:
                await ctx.info("Connecting to Mythic...")
            await session.connect()

    def _format_result(data: Any) -> Any:
        return data

    @mcp.tool()
    async def health_check(ctx: Context) -> Dict[str, Any]:
        """Return basic connection info for the active Mythic session."""
        await _ensure_connection(ctx)
        instance = session.instance
        return {
            "server_ip": config.mythic.server_ip,
            "server_port": config.mythic.server_port,
            "ssl": config.mythic.ssl,
            "current_operation_id": instance.current_operation_id,
        }

    @mcp.tool()
    async def get_all_callbacks(ctx: Context) -> List[Dict[str, Any]]:
        """Get all callbacks for the current operation."""
        await _ensure_connection(ctx)
        return await mythic.get_all_callbacks(mythic=session.instance)

    @mcp.tool()
    async def get_active_callbacks(ctx: Context) -> List[Dict[str, Any]]:
        """Get active callbacks for the current operation."""
        await _ensure_connection(ctx)
        return await mythic.get_all_active_callbacks(mythic=session.instance)

    @mcp.tool()
    async def get_callback_details(ctx: Context, callback_display_id: int) -> Dict[str, Any]:
        """Fetch detailed callback information and recent tasks."""
        await _ensure_connection(ctx)
        query = """
        query GetCallbackDetails($callback_id: Int!) {
            callback(where: {display_id: {_eq: $callback_id}}) {
                id
                display_id
                host
                user
                domain
                os
                architecture
                process_name
                pid
                ip
                external_ip
                integrity_level
                init_callback
                last_checkin
                payload {
                    uuid
                    payloadtype { name }
                }
                tasks(order_by: {id: desc}, limit: 10) {
                    id
                    display_id
                    status
                    completed
                    command { cmd }
                    original_params
                }
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"callback_id": callback_display_id},
        )
        callbacks = result.get("callback", [])
        if not callbacks:
            return {"error": f"No callback found for display_id={callback_display_id}"}
        return callbacks[0]

    @mcp.tool()
    async def issue_task(
        ctx: Context,
        callback_display_id: int,
        command_name: str,
        parameters: Any,
        wait_for_complete: bool = False,
        timeout: int = 60,
        file_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Issue a task to a specific callback."""
        await _ensure_connection(ctx)
        return await mythic.issue_task(
            mythic=session.instance,
            callback_display_id=callback_display_id,
            command_name=command_name,
            parameters=parameters,
            wait_for_complete=wait_for_complete,
            timeout=timeout,
            file_ids=file_ids,
        )

    @mcp.tool()
    async def issue_task_all_active_callbacks(
        ctx: Context,
        command_name: str,
        parameters: Any,
        payload_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Issue a task to all active callbacks, optionally filtered by payload type."""
        await _ensure_connection(ctx)
        return await mythic.issue_task_all_active_callbacks(
            mythic=session.instance,
            command_name=command_name,
            parameters=parameters,
            payload_type=payload_type,
        )

    @mcp.tool()
    async def get_all_tasks(
        ctx: Context, callback_display_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get all tasks, optionally for a specific callback display ID."""
        await _ensure_connection(ctx)
        return await mythic.get_all_tasks(
            mythic=session.instance, callback_display_id=callback_display_id
        )

    @mcp.tool()
    async def get_all_task_output(ctx: Context) -> List[Dict[str, Any]]:
        """Get all task output for the current operation."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for batch in mythic.get_all_task_output(mythic=session.instance):
            results.extend(batch)
        return results

    @mcp.tool()
    async def wait_for_task_output(
        ctx: Context, task_display_id: int, timeout: int = 60
    ) -> Dict[str, Any]:
        """Wait for output for a specific task display ID."""
        await _ensure_connection(ctx)
        output = await mythic.waitfor_for_task_output(
            mythic=session.instance,
            task_display_id=task_display_id,
            timeout=timeout,
        )
        return {"task_display_id": task_display_id, "output": output.decode("utf-8", errors="replace")}

    @mcp.tool()
    async def subscribe_new_callbacks(
        ctx: Context, batch_size: int = 10, timeout: int = 60, max_items: int = 50
    ) -> List[Dict[str, Any]]:
        """Collect new callbacks for a limited time window."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for callback in mythic.subscribe_new_callbacks(
            mythic=session.instance, batch_size=batch_size, timeout=timeout
        ):
            results.append(callback)
            if len(results) >= max_items:
                break
        return results

    @mcp.tool()
    async def subscribe_new_task_output(
        ctx: Context, batch_size: int = 10, timeout: int = 30, max_items: int = 200
    ) -> List[Dict[str, Any]]:
        """Collect new task output for a limited time window."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for responses in mythic.subscribe_new_task_output(
            mythic=session.instance, batch_size=batch_size, timeout=timeout
        ):
            for response in responses:
                results.append(response)
                if len(results) >= max_items:
                    return results
        return results

    @mcp.tool()
    async def create_payload(
        ctx: Context,
        payload_type_name: str,
        filename: str,
        operating_system: str,
        c2_profiles: List[Dict[str, Any]],
        commands: List[str],
        build_parameters: Optional[List[Dict[str, Any]]] = None,
        description: Optional[str] = None,
        return_on_complete: bool = True,
        timeout: int = 120,
        include_all_commands: bool = False,
    ) -> Dict[str, Any]:
        """Create a payload with the provided configuration."""
        await _ensure_connection(ctx)
        return await mythic.create_payload(
            mythic=session.instance,
            payload_type_name=payload_type_name,
            filename=filename,
            operating_system=operating_system,
            c2_profiles=c2_profiles,
            commands=commands,
            build_parameters=build_parameters,
            description=description,
            return_on_complete=return_on_complete,
            timeout=timeout,
            include_all_commands=include_all_commands,
        )

    @mcp.tool()
    async def download_payload(ctx: Context, payload_uuid: str) -> Dict[str, Any]:
        """Download a payload by UUID and return base64-encoded contents."""
        await _ensure_connection(ctx)
        payload_bytes = await mythic.download_payload(
            mythic=session.instance, payload_uuid=payload_uuid
        )
        return {
            "payload_uuid": payload_uuid,
            "content_b64": _bytes_to_b64(payload_bytes),
            "encoding": "base64",
        }

    @mcp.tool()
    async def register_file(
        ctx: Context, filename: str, contents_b64: str, comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """Register a file in Mythic for tasking (content base64)."""
        await _ensure_connection(ctx)
        file_bytes = _b64_to_bytes(contents_b64)
        file_id = await mythic.register_file(
            mythic=session.instance, filename=filename, contents=file_bytes
        )
        return {"file_id": file_id}

    @mcp.tool()
    async def download_file(ctx: Context, file_uuid: str) -> Dict[str, Any]:
        """Download a file by UUID and return base64-encoded contents."""
        await _ensure_connection(ctx)
        file_bytes = await mythic.download_file(
            mythic=session.instance, file_uuid=file_uuid
        )
        return {
            "file_uuid": file_uuid,
            "content_b64": _bytes_to_b64(file_bytes),
            "encoding": "base64",
        }

    @mcp.tool()
    async def get_downloaded_files(
        ctx: Context, batch_size: int = 50
    ) -> List[Dict[str, Any]]:
        """Get metadata for all downloaded files."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for batch in mythic.get_all_downloaded_files(
            mythic=session.instance, batch_size=batch_size
        ):
            results.extend(batch)
        return results

    @mcp.tool()
    async def get_uploaded_files(ctx: Context, batch_size: int = 50) -> List[Dict[str, Any]]:
        """Get metadata for all uploaded files."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for batch in mythic.get_all_uploaded_files(
            mythic=session.instance, batch_size=batch_size
        ):
            results.extend(batch)
        return results

    @mcp.tool()
    async def get_screenshots(ctx: Context) -> List[Dict[str, Any]]:
        """Get metadata for all screenshots."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for screenshot in mythic.get_all_screenshots(mythic=session.instance):
            results.append(screenshot)
        return results

    @mcp.tool()
    async def get_filebrowser(
        ctx: Context, host: Optional[str] = None, batch_size: int = 100
    ) -> List[Dict[str, Any]]:
        """Get file browser entries, optionally for a specific host."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for batch in mythic.get_all_filebrowser(
            mythic=session.instance, host=host, batch_size=batch_size
        ):
            results.extend(batch)
        return results

    @mcp.tool()
    async def get_processes(
        ctx: Context, host: Optional[str] = None, batch_size: int = 100
    ) -> List[Dict[str, Any]]:
        """Get process browser entries, optionally for a specific host."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for batch in mythic.get_all_processes(
            mythic=session.instance, host=host, batch_size=batch_size
        ):
            results.extend(batch)
        return results

    @mcp.tool()
    async def subscribe_new_filebrowser(
        ctx: Context, host: Optional[str] = None, batch_size: int = 50, timeout: int = 60
    ) -> List[Dict[str, Any]]:
        """Collect new file browser entries for a limited time window."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for batch in mythic.subscribe_new_filebrowser(
            mythic=session.instance, host=host, batch_size=batch_size, timeout=timeout
        ):
            results.extend(batch)
        return results

    @mcp.tool()
    async def subscribe_new_processes(
        ctx: Context, host: Optional[str] = None, batch_size: int = 50, timeout: int = 60
    ) -> List[Dict[str, Any]]:
        """Collect new process entries for a limited time window."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for batch in mythic.subscribe_new_processes(
            mythic=session.instance, host=host, batch_size=batch_size, timeout=timeout
        ):
            results.extend(batch)
        return results

    @mcp.tool()
    async def create_credential(
        ctx: Context,
        credential: str,
        account: str,
        realm: str,
        credential_type: str,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a credential in Mythic."""
        await _ensure_connection(ctx)
        return await mythic.create_credential(
            mythic=session.instance,
            credential=credential,
            account=account,
            realm=realm,
            credential_type=credential_type,
            comment=comment,
        )

    @mcp.tool()
    async def get_unique_compromised_hosts(ctx: Context) -> List[str]:
        """Get unique compromised hosts."""
        await _ensure_connection(ctx)
        return await mythic.get_unique_compromised_hosts(mythic=session.instance)

    @mcp.tool()
    async def get_unique_compromised_ips(ctx: Context) -> List[str]:
        """Get unique compromised IPs."""
        await _ensure_connection(ctx)
        return await mythic.get_unique_compromised_ips(mythic=session.instance)

    @mcp.tool()
    async def get_unique_compromised_accounts(ctx: Context) -> List[str]:
        """Get unique compromised accounts."""
        await _ensure_connection(ctx)
        return await mythic.get_unique_compromised_accounts(mythic=session.instance)

    @mcp.tool()
    async def create_operation(ctx: Context, operation_name: str) -> Dict[str, Any]:
        """Create a new operation."""
        await _ensure_connection(ctx)
        return await mythic.create_operation(
            mythic=session.instance, operation_name=operation_name
        )

    @mcp.tool()
    async def update_operation(
        ctx: Context,
        operation_name: str,
        webhook: Optional[str] = None,
        channel: Optional[str] = None,
        complete: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Update operation settings."""
        await _ensure_connection(ctx)
        return await mythic.update_operation(
            mythic=session.instance,
            operation_name=operation_name,
            webhook=webhook,
            channel=channel,
            complete=complete,
        )

    @mcp.tool()
    async def get_operations(ctx: Context) -> List[Dict[str, Any]]:
        """Get all operations."""
        await _ensure_connection(ctx)
        return await mythic.get_operations(mythic=session.instance)

    @mcp.tool()
    async def create_operator(
        ctx: Context,
        username: str,
        password: str,
        email: str,
        bot: bool = False,
    ) -> Dict[str, Any]:
        """Create a new operator."""
        await _ensure_connection(ctx)
        return await mythic.create_operator(
            mythic=session.instance,
            username=username,
            password=password,
            email=email,
            bot=bot,
        )

    @mcp.tool()
    async def add_operator_to_operation(
        ctx: Context, operation_name: str, operator_username: str
    ) -> Dict[str, Any]:
        """Add an operator to an operation."""
        await _ensure_connection(ctx)
        return await mythic.add_operator_to_operation(
            mythic=session.instance,
            operation_name=operation_name,
            operator_username=operator_username,
        )

    @mcp.tool()
    async def remove_operator_from_operation(
        ctx: Context, operation_name: str, operator_username: str
    ) -> Dict[str, Any]:
        """Remove an operator from an operation."""
        await _ensure_connection(ctx)
        return await mythic.remove_operator_from_operation(
            mythic=session.instance,
            operation_name=operation_name,
            operator_username=operator_username,
        )

    @mcp.tool()
    async def update_operator_view_mode(
        ctx: Context,
        operation_name: str,
        operator_username: str,
        view_mode: str,
    ) -> Dict[str, Any]:
        """Update an operator view mode for an operation."""
        await _ensure_connection(ctx)
        return await mythic.update_operator_in_operation(
            mythic=session.instance,
            operation_name=operation_name,
            operator_username=operator_username,
            view_mode=view_mode,
        )

    @mcp.tool()
    async def update_current_operation_for_user(
        ctx: Context, operator_id: int, operation_id: int
    ) -> Dict[str, Any]:
        """Update the current operation for a user."""
        await _ensure_connection(ctx)
        return await mythic.update_current_operation_for_user(
            mythic=session.instance,
            operator_id=operator_id,
            operation_id=operation_id,
        )

    @mcp.tool()
    async def start_stop_c2_profile(
        ctx: Context, c2_profile_name: str, action: str
    ) -> Dict[str, Any]:
        """Start or stop a C2 profile by name."""
        await _ensure_connection(ctx)
        return await mythic.start_stop_c2_profile(
            mythic=session.instance, c2_profile_name=c2_profile_name, action=action
        )

    @mcp.tool()
    async def get_all_payloads(ctx: Context) -> List[Dict[str, Any]]:
        """Get all payloads in the current operation."""
        await _ensure_connection(ctx)
        return await mythic.get_all_payloads(mythic=session.instance)

    @mcp.tool()
    async def get_all_commands_for_payloadtype(
        ctx: Context, payload_type_name: str
    ) -> List[Dict[str, Any]]:
        """Get all commands for a payload type."""
        await _ensure_connection(ctx)
        return await mythic.get_all_commands_for_payloadtype(
            mythic=session.instance, payload_type_name=payload_type_name
        )

    @mcp.tool()
    async def get_all_tag_types(ctx: Context) -> List[Dict[str, Any]]:
        """Get all tag types."""
        await _ensure_connection(ctx)
        resp = await mythic.get_all_tag_types(mythic=session.instance)
        if isinstance(resp, dict) and "tagtype" in resp:
            return resp["tagtype"]
        return resp

    @mcp.tool()
    async def execute_custom_query(
        ctx: Context, query: str, variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a custom GraphQL query."""
        await _ensure_connection(ctx)
        return await mythic.execute_custom_query(
            mythic=session.instance, query=query, variables=variables or {}
        )

    @mcp.tool()
    async def subscribe_custom_query(
        ctx: Context,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        max_items: int = 50,
    ) -> List[Dict[str, Any]]:
        """Collect results from a custom GraphQL subscription for a limited time window."""
        await _ensure_connection(ctx)
        results: List[Dict[str, Any]] = []
        async for result in mythic.subscribe_custom_query(
            mythic=session.instance,
            query=query,
            variables=variables or {},
            timeout=timeout,
        ):
            results.append(result)
            if len(results) >= max_items:
                break
        return results

    return mcp


def _b64_to_bytes(value: str) -> bytes:
    import base64

    return base64.b64decode(value)


def _bytes_to_b64(value: bytes) -> str:
    import base64

    return base64.b64encode(value).decode("utf-8")


async def _run_async(config_path: str) -> None:
    config = load_config(config_path)
    server = _build_server(config)
    await server.run_stdio_async(show_banner=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mythic MCP Server")
    parser.add_argument(
        "--config",
        required=True,
        help="Path to config.yaml",
    )
    args = parser.parse_args()
    asyncio.run(_run_async(args.config))


if __name__ == "__main__":
    main()

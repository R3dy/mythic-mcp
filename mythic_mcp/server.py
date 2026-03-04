from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any, Dict, List, Optional, Union

import yaml
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
        """Fetch detailed callback information including C2 profile and recent tasks."""
        await _ensure_connection(ctx)
        query = """
        query GetCallbackDetails($callback_id: Int!) {
            callback(where: {display_id: {_eq: $callback_id}}) {
                id
                display_id
                active
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
                c2profileparametersinstances {
                    c2_profile_id
                    c2profile {
                        name
                        is_p2p
                        running
                    }
                    enc_key
                    dec_key
                    value
                    c2profileparameter {
                        name
                        key
                    }
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
        cb = callbacks[0]
        # Summarize C2 profiles from parameter instances
        c2_profiles: Dict[str, Any] = {}
        for inst in cb.pop("c2profileparametersinstances", []):
            profile = inst.get("c2profile", {})
            profile_name = profile.get("name", "unknown")
            if profile_name not in c2_profiles:
                c2_profiles[profile_name] = {
                    "c2_profile_id": inst.get("c2_profile_id"),
                    "name": profile_name,
                    "is_p2p": profile.get("is_p2p", False),
                    "running": profile.get("running", False),
                    "parameters": {},
                }
            param = inst.get("c2profileparameter", {})
            param_name = param.get("name") or param.get("key", "")
            if param_name:
                c2_profiles[profile_name]["parameters"][param_name] = inst.get("value")
        cb["c2_profiles"] = list(c2_profiles.values())
        return cb

    @mcp.tool()
    async def get_callback_c2_profiles(
        ctx: Context,
        callback_display_id: int,
    ) -> List[Dict[str, Any]]:
        """Get detailed C2 profile configuration for a specific callback.

        Returns the C2 profiles and their parameter values that the callback
        is using to communicate. Useful for comparing callbacks to identify
        duplicates using the same C2 channel.

        Args:
            callback_display_id: The display ID of the callback.
        """
        await _ensure_connection(ctx)
        query = """
        query GetCallbackC2Profiles($callback_id: Int!) {
            callback(where: {display_id: {_eq: $callback_id}}) {
                id
                display_id
                host
                c2profileparametersinstances {
                    c2_profile_id
                    c2profile {
                        name
                        is_p2p
                        running
                        description
                    }
                    value
                    c2profileparameter {
                        name
                        key
                        description
                    }
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
        cb = callbacks[0]
        c2_profiles: Dict[str, Any] = {}
        for inst in cb.get("c2profileparametersinstances", []):
            profile = inst.get("c2profile", {})
            profile_name = profile.get("name", "unknown")
            if profile_name not in c2_profiles:
                c2_profiles[profile_name] = {
                    "c2_profile_id": inst.get("c2_profile_id"),
                    "name": profile_name,
                    "is_p2p": profile.get("is_p2p", False),
                    "running": profile.get("running", False),
                    "description": profile.get("description", ""),
                    "parameters": {},
                }
            param = inst.get("c2profileparameter", {})
            param_name = param.get("name") or param.get("key", "")
            if param_name:
                c2_profiles[profile_name]["parameters"][param_name] = {
                    "value": inst.get("value"),
                    "description": param.get("description", ""),
                }
        return {
            "callback_display_id": cb["display_id"],
            "host": cb["host"],
            "c2_profiles": list(c2_profiles.values()),
        }

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

    # ---- Event Feed (operationeventlog) tools ----

    @mcp.tool()
    async def get_event_logs(
        ctx: Context,
        level: Optional[str] = None,
        source: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query the operational event log with optional filters.

        Args:
            level: Filter by level (e.g. "info", "warning", "debug").
            source: Filter by source string.
            resolved: Filter by resolved status.
            limit: Maximum number of events to return (default 100).
            offset: Number of events to skip for pagination.
        """
        await _ensure_connection(ctx)
        where_clauses = ["deleted: {_eq: false}"]
        if level is not None:
            where_clauses.append(f'level: {{_eq: "{level}"}}')
        if source is not None:
            where_clauses.append(f'source: {{_eq: "{source}"}}')
        if resolved is not None:
            where_clauses.append(f"resolved: {{_eq: {str(resolved).lower()}}}")
        where = ", ".join(where_clauses)
        query = f"""
        query GetEventLogs($limit: Int!, $offset: Int!) {{
            operationeventlog(
                where: {{{where}}},
                order_by: {{timestamp: desc}},
                limit: $limit,
                offset: $offset
            ) {{
                id
                timestamp
                message
                level
                source
                count
                resolved
                deleted
                operator_id
                operation_id
                operator {{
                    username
                }}
            }}
            operationeventlog_aggregate(where: {{{where}}}) {{
                aggregate {{
                    count
                }}
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"limit": limit, "offset": offset},
        )
        return {
            "events": result.get("operationeventlog", []),
            "total_count": (
                result.get("operationeventlog_aggregate", {})
                .get("aggregate", {})
                .get("count", 0)
            ),
        }

    @mcp.tool()
    async def search_event_logs(
        ctx: Context,
        search_text: str,
        level: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Search event logs by message text using pattern matching.

        Args:
            search_text: Text pattern to search for in event messages (supports SQL ILIKE patterns with %).
            level: Optional level filter.
            resolved: Optional resolved status filter.
            limit: Maximum number of results (default 50).
        """
        await _ensure_connection(ctx)
        where_clauses = [
            "deleted: {_eq: false}",
            'message: {_ilike: $search}',
        ]
        if level is not None:
            where_clauses.append(f'level: {{_eq: "{level}"}}')
        if resolved is not None:
            where_clauses.append(f"resolved: {{_eq: {str(resolved).lower()}}}")
        where = ", ".join(where_clauses)
        pattern = f"%{search_text}%" if "%" not in search_text else search_text
        query = f"""
        query SearchEventLogs($search: String!, $limit: Int!) {{
            operationeventlog(
                where: {{{where}}},
                order_by: {{timestamp: desc}},
                limit: $limit
            ) {{
                id
                timestamp
                message
                level
                source
                count
                resolved
                operator_id
                operator {{
                    username
                }}
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"search": pattern, "limit": limit},
        )
        return result.get("operationeventlog", [])

    @mcp.tool()
    async def send_event_log(
        ctx: Context,
        message: str,
        level: str = "info",
        source: str = "",
    ) -> Dict[str, Any]:
        """Send a new entry to the operational event log.

        Args:
            message: The event message text.
            level: Log level - "info", "warning", or "debug" (default "info").
            source: Optional source identifier for the event.
        """
        await _ensure_connection(ctx)
        return await mythic.send_event_log_message(
            mythic=session.instance,
            message=message,
            level=level,
            source=source,
        )

    @mcp.tool()
    async def resolve_event_log(
        ctx: Context,
        event_id: int,
    ) -> Dict[str, Any]:
        """Mark an event log entry as resolved.

        Args:
            event_id: The ID of the event log entry to resolve.
        """
        await _ensure_connection(ctx)
        query = """
        mutation ResolveEventLog($id: Int!) {
            update_operationeventlog_by_pk(
                pk_columns: {id: $id},
                _set: {resolved: true}
            ) {
                id
                resolved
                message
                level
            }
        }
        """
        return await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_id},
        )

    @mcp.tool()
    async def unresolve_event_log(
        ctx: Context,
        event_id: int,
    ) -> Dict[str, Any]:
        """Mark an event log entry as unresolved (reopen it).

        Args:
            event_id: The ID of the event log entry to unresolve.
        """
        await _ensure_connection(ctx)
        query = """
        mutation UnresolveEventLog($id: Int!) {
            update_operationeventlog_by_pk(
                pk_columns: {id: $id},
                _set: {resolved: false}
            ) {
                id
                resolved
                message
                level
            }
        }
        """
        return await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_id},
        )

    @mcp.tool()
    async def delete_event_log(
        ctx: Context,
        event_id: int,
    ) -> Dict[str, Any]:
        """Soft-delete an event log entry.

        Args:
            event_id: The ID of the event log entry to delete.
        """
        await _ensure_connection(ctx)
        query = """
        mutation DeleteEventLog($id: Int!) {
            update_operationeventlog_by_pk(
                pk_columns: {id: $id},
                _set: {deleted: true}
            ) {
                id
                deleted
                message
            }
        }
        """
        return await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_id},
        )

    @mcp.tool()
    async def subscribe_event_logs(
        ctx: Context,
        level: Optional[str] = None,
        timeout: int = 60,
        max_items: int = 100,
    ) -> List[Dict[str, Any]]:
        """Subscribe to real-time event log entries for a limited time window.

        Args:
            level: Optional filter by level (e.g. "info", "warning").
            timeout: Seconds to listen before returning (default 60).
            max_items: Maximum events to collect (default 100).
        """
        await _ensure_connection(ctx)
        where_clause = "deleted: {_eq: false}"
        if level is not None:
            where_clause += f', level: {{_eq: "{level}"}}'
        query = f"""
        subscription EventLogStream {{
            operationeventlog_stream(
                batch_size: 10,
                cursor: {{initial_value: {{timestamp: "now()"}}}},
                where: {{{where_clause}}}
            ) {{
                id
                timestamp
                message
                level
                source
                count
                resolved
                operator_id
                operator {{
                    username
                }}
            }}
        }}
        """
        results: List[Dict[str, Any]] = []
        async for batch in mythic.subscribe_custom_query(
            mythic=session.instance,
            query=query,
            variables={},
            timeout=timeout,
        ):
            if isinstance(batch, list):
                results.extend(batch)
            else:
                results.append(batch)
            if len(results) >= max_items:
                break
        return results

    # ---- Workflow Eventing (eventgroup / eventstep) tools ----

    @mcp.tool()
    async def get_event_groups(
        ctx: Context,
        active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """Get all workflow event groups (eventing definitions).

        Args:
            active: Optional filter by active status.
        """
        await _ensure_connection(ctx)
        where_clause = ""
        if active is not None:
            where_clause = f"(where: {{active: {{_eq: {str(active).lower()}}}}})"
        query = f"""
        query GetEventGroups {{
            eventgroup{where_clause} {{
                id
                name
                description
                active
                trigger
                trigger_data
                keywords
                operation_id
                fileid
                eventsteps {{
                    id
                    name
                    description
                    action
                    action_data
                    depends_on
                    order
                }}
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={},
        )
        return result.get("eventgroup", [])

    @mcp.tool()
    async def get_event_group_details(
        ctx: Context,
        event_group_id: int,
    ) -> Dict[str, Any]:
        """Get detailed information about a specific workflow event group including its steps.

        Args:
            event_group_id: The ID of the event group to query.
        """
        await _ensure_connection(ctx)
        query = """
        query GetEventGroupDetails($id: Int!) {
            eventgroup_by_pk(id: $id) {
                id
                name
                description
                active
                trigger
                trigger_data
                keywords
                operation_id
                fileid
                eventsteps(order_by: {order: asc}) {
                    id
                    name
                    description
                    action
                    action_data
                    depends_on
                    environment
                    inputs
                    outputs
                    order
                }
                eventgroupinstances(order_by: {id: desc}, limit: 10) {
                    id
                    status
                    trigger
                    created_at
                    updated_at
                }
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_group_id},
        )
        data = result.get("eventgroup_by_pk")
        if not data:
            return {"error": f"No event group found with id={event_group_id}"}
        return data

    @mcp.tool()
    async def get_event_group_instances(
        ctx: Context,
        event_group_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get workflow execution instances.

        Args:
            event_group_id: Optional filter by event group ID.
            status: Optional filter by status (e.g. "running", "completed", "error").
            limit: Maximum instances to return (default 50).
        """
        await _ensure_connection(ctx)
        where_parts = []
        if event_group_id is not None:
            where_parts.append(f"eventgroup_id: {{_eq: {event_group_id}}}")
        if status is not None:
            where_parts.append(f'status: {{_eq: "{status}"}}')
        where_clause = ""
        if where_parts:
            where_clause = f"where: {{{', '.join(where_parts)}}},"
        query = f"""
        query GetEventGroupInstances($limit: Int!) {{
            eventgroupinstance(
                {where_clause}
                order_by: {{id: desc}},
                limit: $limit
            ) {{
                id
                eventgroup_id
                status
                trigger
                created_at
                updated_at
                eventgroup {{
                    name
                    trigger
                }}
                eventstepinstances(order_by: {{id: asc}}) {{
                    id
                    eventstep_id
                    status
                    start_timestamp
                    end_timestamp
                    stdout
                    stderr
                    eventstep {{
                        name
                        action
                    }}
                }}
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"limit": limit},
        )
        return result.get("eventgroupinstance", [])

    @mcp.tool()
    async def get_event_step_instance_output(
        ctx: Context,
        event_step_instance_id: int,
    ) -> Dict[str, Any]:
        """Get detailed output for a specific workflow step execution.

        Args:
            event_step_instance_id: The ID of the event step instance.
        """
        await _ensure_connection(ctx)
        query = """
        query GetEventStepInstanceOutput($id: Int!) {
            eventstepinstance_by_pk(id: $id) {
                id
                eventstep_id
                status
                start_timestamp
                end_timestamp
                stdout
                stderr
                eventstep {
                    name
                    description
                    action
                    action_data
                }
                eventgroupinstance {
                    id
                    status
                    eventgroup {
                        name
                    }
                }
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_step_instance_id},
        )
        data = result.get("eventstepinstance_by_pk")
        if not data:
            return {"error": f"No event step instance found with id={event_step_instance_id}"}
        return data

    @mcp.tool()
    async def toggle_event_group(
        ctx: Context,
        event_group_id: int,
        active: bool,
    ) -> Dict[str, Any]:
        """Enable or disable a workflow event group.

        Args:
            event_group_id: The ID of the event group.
            active: True to enable, False to disable.
        """
        await _ensure_connection(ctx)
        query = """
        mutation ToggleEventGroup($id: Int!, $active: Boolean!) {
            update_eventgroup_by_pk(
                pk_columns: {id: $id},
                _set: {active: $active}
            ) {
                id
                name
                active
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_group_id, "active": active},
        )
        data = result.get("update_eventgroup_by_pk")
        if not data:
            return {"error": f"No event group found with id={event_group_id}"}
        return data

    @mcp.tool()
    async def trigger_event_group(
        ctx: Context,
        event_group_id: int,
        environment: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Manually trigger a workflow event group to run.

        Creates a new event group instance for a manual or keyword-triggered workflow.

        Args:
            event_group_id: The ID of the event group to trigger.
            environment: Optional dictionary of environment variables for the run.
        """
        await _ensure_connection(ctx)
        env_data = environment or {}
        query = """
        mutation TriggerEventGroup($eventgroup_id: Int!, $environment: jsonb!) {
            insert_eventgroupinstance_one(
                object: {
                    eventgroup_id: $eventgroup_id,
                    trigger: "manual",
                    environment: $environment
                }
            ) {
                id
                status
                trigger
                created_at
                eventgroup {
                    name
                }
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={
                "eventgroup_id": event_group_id,
                "environment": env_data,
            },
        )
        data = result.get("insert_eventgroupinstance_one")
        if not data:
            return {"error": "Failed to trigger event group. Check that the event group exists and you have permission."}
        return data

    @mcp.tool()
    async def subscribe_event_group_instances(
        ctx: Context,
        event_group_id: Optional[int] = None,
        timeout: int = 60,
        max_items: int = 50,
    ) -> List[Dict[str, Any]]:
        """Subscribe to real-time workflow execution updates.

        Args:
            event_group_id: Optional filter to a specific event group.
            timeout: Seconds to listen (default 60).
            max_items: Maximum instances to collect (default 50).
        """
        await _ensure_connection(ctx)
        where_clause = ""
        if event_group_id is not None:
            where_clause = f"where: {{eventgroup_id: {{_eq: {event_group_id}}}}}, "
        query = f"""
        subscription EventGroupInstanceStream {{
            eventgroupinstance_stream(
                batch_size: 10,
                cursor: {{initial_value: {{id: 0}}}},
                {where_clause}
            ) {{
                id
                eventgroup_id
                status
                trigger
                created_at
                updated_at
                eventgroup {{
                    name
                }}
            }}
        }}
        """
        results: List[Dict[str, Any]] = []
        async for batch in mythic.subscribe_custom_query(
            mythic=session.instance,
            query=query,
            variables={},
            timeout=timeout,
        ):
            if isinstance(batch, list):
                results.extend(batch)
            else:
                results.append(batch)
            if len(results) >= max_items:
                break
        return results

    # ---- Eventing CRUD tools ----

    @mcp.tool()
    async def create_event_group(
        ctx: Context,
        name: str,
        trigger: str,
        description: str = "",
        trigger_data: Optional[Dict[str, Any]] = None,
        keywords: Optional[List[str]] = None,
        active: bool = True,
        environment: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Create a new workflow event group (eventing definition).

        An event group defines a workflow that is triggered by an event in Mythic.
        After creating the group, add steps with create_event_step.

        Args:
            name: Unique name for the event group.
            trigger: Trigger type. One of: "callback_new", "manual", "cron",
                "mythic_start", "callback_checkin", "payload_build_start",
                "payload_build_finish", "task_create", "task_finish",
                "user_output", "task_intercept", "response_intercept", "alert".
            description: Human-readable description of the workflow.
            trigger_data: Additional trigger config. Common keys:
                "payload_types" (list of payload type names to filter on),
                "selected_os" (list of OS names to filter on).
            keywords: List of keyword strings that can also trigger this workflow
                (from UI, agent responses, or callback context menu).
            active: Whether the event group is active (default True).
            environment: Default environment variables for all steps.
        """
        await _ensure_connection(ctx)
        obj_parts = [
            f'name: "{name}"',
            f'trigger: "{trigger}"',
            f'description: "{description}"',
            f"active: {str(active).lower()}",
        ]
        variables: Dict[str, Any] = {}
        var_defs = []
        if trigger_data is not None:
            var_defs.append("$trigger_data: jsonb!")
            obj_parts.append("trigger_data: $trigger_data")
            variables["trigger_data"] = trigger_data
        if keywords is not None:
            var_defs.append("$keywords: jsonb!")
            obj_parts.append("keywords: $keywords")
            variables["keywords"] = keywords
        if environment is not None:
            var_defs.append("$environment: jsonb!")
            obj_parts.append("environment: $environment")
            variables["environment"] = environment
        var_def_str = f"({', '.join(var_defs)})" if var_defs else ""
        obj_str = ", ".join(obj_parts)
        query = f"""
        mutation CreateEventGroup{var_def_str} {{
            insert_eventgroup_one(object: {{{obj_str}}}) {{
                id
                name
                description
                active
                trigger
                trigger_data
                keywords
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables=variables,
        )
        data = result.get("insert_eventgroup_one")
        if not data:
            return {"error": "Failed to create event group. Check permissions and that the name is unique."}
        return data

    @mcp.tool()
    async def create_event_step(
        ctx: Context,
        event_group_id: int,
        name: str,
        action: str,
        action_data: Dict[str, Any],
        order: int = 0,
        description: str = "",
        depends_on: Optional[List[str]] = None,
        inputs: Optional[Dict[str, str]] = None,
        outputs: Optional[Dict[str, str]] = None,
        environment: Optional[Dict[str, str]] = None,
        continue_on_error: bool = False,
    ) -> Dict[str, Any]:
        """Create a new step in a workflow event group.

        Steps define the actions taken when a workflow is triggered. They execute
        in order, respecting depends_on relationships.

        Args:
            event_group_id: ID of the event group to add the step to.
            name: Unique name for this step within the event group.
            action: Action type. One of: "task_create", "custom_function",
                "conditional_check", "task_intercept", "response_intercept".
            action_data: Action-specific configuration.
                For task_create: {"callback_display_id": "CALLBACK_ID",
                 "command_name": "cmd", "params": "json_string"}.
                For custom_function: {"container_name": "hydra",
                 "function_name": "execute_script"}.
                For conditional_check: {"container_name": "hydra",
                 "function_name": "conditional_check", "steps": ["step_name"]}.
                For task_intercept/response_intercept:
                 {"container_name": "hydra"}.
            order: Execution order (0-based, default 0).
            description: Human-readable description of the step.
            depends_on: List of step names this step depends on.
            inputs: Input mapping dict. Keys are placeholders in action_data,
                values are sources. Supported prefixes:
                "env.<key>" (trigger environment data, e.g. "env.display_id"),
                "mythic.apitoken" (per-step API token for GraphQL access),
                "upload.<filename>" (agent_file_id of uploaded file),
                "download.<filename>" (agent_file_id of downloaded file),
                "workflow.<filename>" (file attached to the workflow),
                "<step_name>.<output_key>" (output from a prior step).
            outputs: Output mapping dict for passing data to dependent steps.
            environment: Per-step environment variables.
            continue_on_error: Whether to continue workflow if this step fails.
        """
        await _ensure_connection(ctx)
        variables: Dict[str, Any] = {
            "eventgroup_id": event_group_id,
            "action_data": action_data,
        }
        var_defs = [
            "$eventgroup_id: Int!",
            "$action_data: jsonb!",
        ]
        obj_parts = [
            "eventgroup_id: $eventgroup_id",
            f'name: "{name}"',
            f'action: "{action}"',
            "action_data: $action_data",
            f"order: {order}",
            f'description: "{description}"',
            f"continue_on_error: {str(continue_on_error).lower()}",
        ]
        if depends_on is not None:
            var_defs.append("$depends_on: jsonb!")
            obj_parts.append("depends_on: $depends_on")
            variables["depends_on"] = depends_on
        if inputs is not None:
            var_defs.append("$inputs: jsonb!")
            obj_parts.append("inputs: $inputs")
            variables["inputs"] = inputs
        if outputs is not None:
            var_defs.append("$outputs: jsonb!")
            obj_parts.append("outputs: $outputs")
            variables["outputs"] = outputs
        if environment is not None:
            var_defs.append("$environment: jsonb!")
            obj_parts.append("environment: $environment")
            variables["environment"] = environment
        var_def_str = f"({', '.join(var_defs)})"
        obj_str = ", ".join(obj_parts)
        query = f"""
        mutation CreateEventStep{var_def_str} {{
            insert_eventstep_one(object: {{{obj_str}}}) {{
                id
                name
                description
                action
                action_data
                order
                depends_on
                inputs
                outputs
                environment
                continue_on_error
                eventgroup_id
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables=variables,
        )
        data = result.get("insert_eventstep_one")
        if not data:
            return {"error": "Failed to create event step. Check that the event group exists and step name is unique within it."}
        return data

    @mcp.tool()
    async def update_event_group(
        ctx: Context,
        event_group_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        trigger: Optional[str] = None,
        trigger_data: Optional[Dict[str, Any]] = None,
        keywords: Optional[List[str]] = None,
        active: Optional[bool] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Update an existing workflow event group's configuration.

        Only provided fields are updated; omitted fields remain unchanged.

        Args:
            event_group_id: The ID of the event group to update.
            name: New name for the event group.
            description: New description.
            trigger: New trigger type.
            trigger_data: New trigger configuration data.
            keywords: New list of keywords.
            active: Whether the group is active.
            environment: New default environment variables.
        """
        await _ensure_connection(ctx)
        set_parts = []
        variables: Dict[str, Any] = {"id": event_group_id}
        var_defs = ["$id: Int!"]
        if name is not None:
            set_parts.append("name: $name")
            var_defs.append("$name: String!")
            variables["name"] = name
        if description is not None:
            set_parts.append("description: $description")
            var_defs.append("$description: String!")
            variables["description"] = description
        if trigger is not None:
            set_parts.append("trigger: $trigger")
            var_defs.append("$trigger: String!")
            variables["trigger"] = trigger
        if trigger_data is not None:
            set_parts.append("trigger_data: $trigger_data")
            var_defs.append("$trigger_data: jsonb!")
            variables["trigger_data"] = trigger_data
        if keywords is not None:
            set_parts.append("keywords: $keywords")
            var_defs.append("$keywords: jsonb!")
            variables["keywords"] = keywords
        if active is not None:
            set_parts.append("active: $active")
            var_defs.append("$active: Boolean!")
            variables["active"] = active
        if environment is not None:
            set_parts.append("environment: $environment")
            var_defs.append("$environment: jsonb!")
            variables["environment"] = environment
        if not set_parts:
            return {"error": "No fields provided to update."}
        set_str = ", ".join(set_parts)
        var_def_str = f"({', '.join(var_defs)})"
        query = f"""
        mutation UpdateEventGroup{var_def_str} {{
            update_eventgroup_by_pk(
                pk_columns: {{id: $id}},
                _set: {{{set_str}}}
            ) {{
                id
                name
                description
                active
                trigger
                trigger_data
                keywords
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables=variables,
        )
        data = result.get("update_eventgroup_by_pk")
        if not data:
            return {"error": f"No event group found with id={event_group_id}"}
        return data

    @mcp.tool()
    async def update_event_step(
        ctx: Context,
        event_step_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        action: Optional[str] = None,
        action_data: Optional[Dict[str, Any]] = None,
        order: Optional[int] = None,
        depends_on: Optional[List[str]] = None,
        inputs: Optional[Dict[str, str]] = None,
        outputs: Optional[Dict[str, str]] = None,
        environment: Optional[Dict[str, str]] = None,
        continue_on_error: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Update an existing workflow event step's configuration.

        Only provided fields are updated; omitted fields remain unchanged.

        Args:
            event_step_id: The ID of the event step to update.
            name: New step name.
            description: New description.
            action: New action type ("task_create", "custom_function", "conditional_check").
            action_data: New action configuration.
            order: New execution order.
            depends_on: New dependency list (step names).
            inputs: New input mappings.
            outputs: New output mappings.
            environment: New per-step environment variables.
            continue_on_error: Whether to continue on error.
        """
        await _ensure_connection(ctx)
        set_parts = []
        variables: Dict[str, Any] = {"id": event_step_id}
        var_defs = ["$id: Int!"]
        if name is not None:
            set_parts.append("name: $name")
            var_defs.append("$name: String!")
            variables["name"] = name
        if description is not None:
            set_parts.append("description: $description")
            var_defs.append("$description: String!")
            variables["description"] = description
        if action is not None:
            set_parts.append("action: $action")
            var_defs.append("$action: String!")
            variables["action"] = action
        if action_data is not None:
            set_parts.append("action_data: $action_data")
            var_defs.append("$action_data: jsonb!")
            variables["action_data"] = action_data
        if order is not None:
            set_parts.append("order: $order")
            var_defs.append("$order: Int!")
            variables["order"] = order
        if depends_on is not None:
            set_parts.append("depends_on: $depends_on")
            var_defs.append("$depends_on: jsonb!")
            variables["depends_on"] = depends_on
        if inputs is not None:
            set_parts.append("inputs: $inputs")
            var_defs.append("$inputs: jsonb!")
            variables["inputs"] = inputs
        if outputs is not None:
            set_parts.append("outputs: $outputs")
            var_defs.append("$outputs: jsonb!")
            variables["outputs"] = outputs
        if environment is not None:
            set_parts.append("environment: $environment")
            var_defs.append("$environment: jsonb!")
            variables["environment"] = environment
        if continue_on_error is not None:
            set_parts.append("continue_on_error: $continue_on_error")
            var_defs.append("$continue_on_error: Boolean!")
            variables["continue_on_error"] = continue_on_error
        if not set_parts:
            return {"error": "No fields provided to update."}
        set_str = ", ".join(set_parts)
        var_def_str = f"({', '.join(var_defs)})"
        query = f"""
        mutation UpdateEventStep{var_def_str} {{
            update_eventstep_by_pk(
                pk_columns: {{id: $id}},
                _set: {{{set_str}}}
            ) {{
                id
                name
                description
                action
                action_data
                order
                depends_on
                inputs
                outputs
                environment
                continue_on_error
                eventgroup_id
            }}
        }}
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables=variables,
        )
        data = result.get("update_eventstep_by_pk")
        if not data:
            return {"error": f"No event step found with id={event_step_id}"}
        return data

    @mcp.tool()
    async def delete_event_group(
        ctx: Context,
        event_group_id: int,
    ) -> Dict[str, Any]:
        """Delete a workflow event group and all its steps.

        This permanently removes the event group definition and all associated
        event steps. Event group instances (execution history) are preserved.

        Args:
            event_group_id: The ID of the event group to delete.
        """
        await _ensure_connection(ctx)
        # Delete steps first, then the group
        delete_steps_query = """
        mutation DeleteEventSteps($eventgroup_id: Int!) {
            delete_eventstep(where: {eventgroup_id: {_eq: $eventgroup_id}}) {
                affected_rows
            }
        }
        """
        steps_result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=delete_steps_query,
            variables={"eventgroup_id": event_group_id},
        )
        steps_deleted = (
            steps_result.get("delete_eventstep", {}).get("affected_rows", 0)
        )
        delete_group_query = """
        mutation DeleteEventGroup($id: Int!) {
            delete_eventgroup_by_pk(id: $id) {
                id
                name
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=delete_group_query,
            variables={"id": event_group_id},
        )
        data = result.get("delete_eventgroup_by_pk")
        if not data:
            return {"error": f"No event group found with id={event_group_id}"}
        return {
            "deleted_group": data,
            "steps_deleted": steps_deleted,
        }

    @mcp.tool()
    async def delete_event_step(
        ctx: Context,
        event_step_id: int,
    ) -> Dict[str, Any]:
        """Delete a single step from a workflow event group.

        Args:
            event_step_id: The ID of the event step to delete.
        """
        await _ensure_connection(ctx)
        query = """
        mutation DeleteEventStep($id: Int!) {
            delete_eventstep_by_pk(id: $id) {
                id
                name
                eventgroup_id
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_step_id},
        )
        data = result.get("delete_eventstep_by_pk")
        if not data:
            return {"error": f"No event step found with id={event_step_id}"}
        return data

    @mcp.tool()
    async def import_event_group(
        ctx: Context,
        workflow_definition: str,
        format: str = "yaml",
        active: bool = True,
    ) -> Dict[str, Any]:
        """Import a complete workflow event group from a YAML, JSON, or TOML definition.

        Parses a workflow definition string (in the same format used by Mythic's
        eventing system and the Pantheon project) and creates the event group
        and all its steps.

        The expected structure matches Mythic's eventing file format:
            name: "Workflow Name"
            description: "What it does"
            trigger: callback_new
            trigger_data:
              payload_types: [apollo]
            keywords: [keyword1]
            environment: {}
            steps:
              - name: "Step 1"
                action: task_create
                inputs:
                  CALLBACK_ID: env.display_id
                action_data:
                  callback_display_id: CALLBACK_ID
                  command_name: whoami
                depends_on: []
                continue_on_error: false

        Args:
            workflow_definition: The workflow definition string.
            format: Format of the definition: "yaml", "json", or "toml" (default "yaml").
            active: Whether the imported group should be active (default True).
        """
        await _ensure_connection(ctx)
        if format == "yaml":
            defn = yaml.safe_load(workflow_definition)
        elif format == "json":
            defn = json.loads(workflow_definition)
        elif format == "toml":
            import tomllib
            defn = tomllib.loads(workflow_definition)
        else:
            return {"error": f"Unsupported format: {format}. Use 'yaml', 'json', or 'toml'."}

        if not isinstance(defn, dict):
            return {"error": "Workflow definition must be a mapping/object at the top level."}

        # Build the event group object for insertion
        group_obj: Dict[str, Any] = {
            "name": defn.get("name", "Unnamed Workflow"),
            "description": defn.get("description", ""),
            "trigger": defn.get("trigger", "manual"),
            "active": active,
        }
        if "trigger_data" in defn:
            group_obj["trigger_data"] = defn["trigger_data"]
        if "keywords" in defn:
            group_obj["keywords"] = defn["keywords"]
        if "environment" in defn:
            group_obj["environment"] = defn["environment"]

        # Build steps with nested insert
        steps = defn.get("steps", [])
        step_objects = []
        for idx, step in enumerate(steps):
            step_obj: Dict[str, Any] = {
                "name": step.get("name", f"step_{idx}"),
                "action": step.get("action", "task_create"),
                "order": idx,
            }
            if "description" in step:
                step_obj["description"] = step["description"]
            if "action_data" in step:
                ad = step["action_data"]
                # Ensure params is a string (YAML may parse it as dict)
                if "params" in ad and not isinstance(ad["params"], str):
                    ad["params"] = json.dumps(ad["params"])
                step_obj["action_data"] = ad
            if "depends_on" in step:
                step_obj["depends_on"] = step["depends_on"]
            if "inputs" in step:
                step_obj["inputs"] = step["inputs"]
            if "outputs" in step:
                step_obj["outputs"] = step["outputs"]
            if "environment" in step:
                step_obj["environment"] = step["environment"]
            if "continue_on_error" in step:
                step_obj["continue_on_error"] = step["continue_on_error"]
            step_objects.append(step_obj)

        if step_objects:
            group_obj["eventsteps"] = {"data": step_objects}

        query = """
        mutation ImportEventGroup($object: eventgroup_insert_input!) {
            insert_eventgroup_one(object: $object) {
                id
                name
                description
                active
                trigger
                trigger_data
                keywords
                eventsteps(order_by: {order: asc}) {
                    id
                    name
                    action
                    action_data
                    order
                    depends_on
                    inputs
                    outputs
                    continue_on_error
                }
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"object": group_obj},
        )
        data = result.get("insert_eventgroup_one")
        if not data:
            return {"error": "Failed to import event group. Check the definition format and permissions."}
        return data

    @mcp.tool()
    async def export_event_group(
        ctx: Context,
        event_group_id: int,
        format: str = "yaml",
    ) -> Union[str, Dict[str, Any]]:
        """Export a workflow event group as a YAML or JSON definition string.

        Produces a definition compatible with Mythic's eventing file format
        and the Pantheon project. Can be saved to a file and re-imported.

        Args:
            event_group_id: The ID of the event group to export.
            format: Output format: "yaml" or "json" (default "yaml").
        """
        await _ensure_connection(ctx)
        query = """
        query ExportEventGroup($id: Int!) {
            eventgroup_by_pk(id: $id) {
                name
                description
                trigger
                trigger_data
                keywords
                eventsteps(order_by: {order: asc}) {
                    name
                    description
                    action
                    action_data
                    order
                    depends_on
                    inputs
                    outputs
                    environment
                    continue_on_error
                }
            }
        }
        """
        result = await mythic.execute_custom_query(
            mythic=session.instance,
            query=query,
            variables={"id": event_group_id},
        )
        data = result.get("eventgroup_by_pk")
        if not data:
            return {"error": f"No event group found with id={event_group_id}"}

        # Build clean export structure
        export: Dict[str, Any] = {
            "name": data["name"],
            "description": data.get("description", ""),
            "trigger": data["trigger"],
        }
        if data.get("trigger_data"):
            export["trigger_data"] = data["trigger_data"]
        if data.get("keywords"):
            export["keywords"] = data["keywords"]
        export["environment"] = {}

        steps = []
        for step in data.get("eventsteps", []):
            step_export: Dict[str, Any] = {
                "name": step["name"],
            }
            if step.get("description"):
                step_export["description"] = step["description"]
            if step.get("continue_on_error"):
                step_export["continue_on_error"] = step["continue_on_error"]
            if step.get("inputs"):
                step_export["inputs"] = step["inputs"]
            step_export["action"] = step["action"]
            if step.get("depends_on"):
                step_export["depends_on"] = step["depends_on"]
            if step.get("action_data"):
                step_export["action_data"] = step["action_data"]
            if step.get("environment"):
                step_export["environment"] = step["environment"]
            if step.get("outputs"):
                step_export["outputs"] = step["outputs"]
            steps.append(step_export)

        export["steps"] = steps

        if format == "json":
            return {"format": "json", "definition": json.dumps(export, indent=2)}
        return {"format": "yaml", "definition": yaml.dump(export, default_flow_style=False, sort_keys=False)}

    # ---- Custom query tools (existing) ----

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

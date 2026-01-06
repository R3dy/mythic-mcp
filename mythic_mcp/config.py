from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Dict
import yaml


@dataclass
class MythicConfig:
    server_ip: str
    server_port: int
    ssl: bool
    username: str
    password: str
    apitoken: str
    timeout: int
    logging_level: int


@dataclass
class MCPConfig:
    name: str
    instructions: str


@dataclass
class AppConfig:
    mythic: MythicConfig
    mcp: MCPConfig


def _env_override(data: Dict[str, Any], key: str, env_key: str) -> None:
    value = os.getenv(env_key)
    if value is None:
        return
    data[key] = value


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    mythic_raw = raw.get("mythic", {})
    mcp_raw = raw.get("mcp", {})

    _env_override(mythic_raw, "server_ip", "MYTHIC_SERVER_IP")
    _env_override(mythic_raw, "server_port", "MYTHIC_SERVER_PORT")
    _env_override(mythic_raw, "ssl", "MYTHIC_SSL")
    _env_override(mythic_raw, "username", "MYTHIC_USERNAME")
    _env_override(mythic_raw, "password", "MYTHIC_PASSWORD")
    _env_override(mythic_raw, "apitoken", "MYTHIC_APITOKEN")
    _env_override(mythic_raw, "timeout", "MYTHIC_TIMEOUT")
    _env_override(mythic_raw, "logging_level", "MYTHIC_LOGGING_LEVEL")

    if isinstance(mythic_raw.get("server_port"), str):
        mythic_raw["server_port"] = int(mythic_raw["server_port"])
    if isinstance(mythic_raw.get("timeout"), str):
        mythic_raw["timeout"] = int(mythic_raw["timeout"])
    if isinstance(mythic_raw.get("logging_level"), str):
        mythic_raw["logging_level"] = int(mythic_raw["logging_level"])
    if isinstance(mythic_raw.get("ssl"), str):
        mythic_raw["ssl"] = mythic_raw["ssl"].lower() in {"1", "true", "yes"}

    mythic = MythicConfig(
        server_ip=mythic_raw.get("server_ip", "127.0.0.1"),
        server_port=int(mythic_raw.get("server_port", 7443)),
        ssl=bool(mythic_raw.get("ssl", True)),
        username=str(mythic_raw.get("username", "mythic_admin")),
        password=str(mythic_raw.get("password", "")),
        apitoken=str(mythic_raw.get("apitoken", "")),
        timeout=int(mythic_raw.get("timeout", -1)),
        logging_level=int(mythic_raw.get("logging_level", 20)),
    )

    mcp = MCPConfig(
        name=str(mcp_raw.get("name", "mythic_mcp")),
        instructions=str(mcp_raw.get("instructions", "Mythic C2 operator tools for MCP")),
    )

    return AppConfig(mythic=mythic, mcp=mcp)

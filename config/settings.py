"""
Settings loader — merges .env file and config.yaml into a single typed config object.
Usage anywhere in the project:
    from config.settings import get_settings
    settings = get_settings()
    print(settings.api_port)
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from pydantic import Field

logger = logging.getLogger("astra.settings")


# ---------------------------------------------------------------------------
# Locate project root (directory containing config.yaml)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_yaml_config(field_names: set[str] | None = None) -> dict:
    """Flatten config.yaml onto Settings field names.

    The previous version flattened every nested key to its LEAF name, so
    `database.url` and `redis.url` both became `url` — redis won by dict order,
    and neither matched a field, so `extra: "ignore"` silently dropped both.
    The same happened to `redis.enabled`, `database.echo` and the whole
    `scoring.weights` block: config.yaml looked like configuration but almost
    none of it took effect.

    Naming is inconsistent in the file (`server.api_host` maps to the field
    `api_host`, but `database.url` maps to `database_url`), so try the
    section-prefixed name first and fall back to the bare key. Anything that
    matches neither is reported rather than silently discarded.
    """
    config_path = PROJECT_ROOT / "config.yaml"
    if not config_path.exists():
        return {}
    with open(config_path, "r") as f:
        raw = yaml.safe_load(f) or {}

    fields = field_names if field_names is not None else set(Settings.model_fields)
    flat: dict = {}
    unmapped: list[str] = []

    for section, values in raw.items():
        if not isinstance(values, dict):
            if section in fields:
                flat[section] = values
            else:
                unmapped.append(section)
            continue

        for key, val in values.items():
            prefixed = f"{section}_{key}"
            if prefixed in fields:
                flat[prefixed] = val
            elif key in fields:
                flat[key] = val
            else:
                unmapped.append(f"{section}.{key}")

    if unmapped:
        logger.warning(
            "[settings] config.yaml keys with no matching setting (ignored): %s",
            ", ".join(sorted(unmapped)),
        )
    return flat


class _YamlSettingsSource(PydanticBaseSettingsSource):
    """config.yaml as the LOWEST-priority source.

    These values used to be passed to Settings(**yaml) as init kwargs, which
    pydantic-settings ranks ABOVE environment variables — so config.yaml
    silently overrode .env and real env vars, the exact opposite of what the
    module docstring promised.
    """

    def get_field_value(self, field, field_name):  # pragma: no cover - unused hook
        return None, field_name, False

    def __call__(self) -> dict:
        values = _load_yaml_config(set(self.settings_cls.model_fields))
        return {k: v for k, v in values.items() if v is not None}


# ---------------------------------------------------------------------------
# Settings model
# ---------------------------------------------------------------------------
class Settings(BaseSettings):
    """Unified app settings — .env values override config.yaml defaults."""

    # App
    app_name: str = "ASTRA"
    app_env: str = "production"
    version: str = "0.1.0"
    debug: bool = False

    # Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    dashboard_port: int = 8050
    reload: bool = False

    # Database
    database_url: str = "sqlite+aiosqlite:///./astra.db"
    db_echo: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_enabled: bool = False

    # Simulation
    default_difficulty: str = "medium"
    log_stream_interval_ms: int = 500
    noise_ratio: float = 0.6
    max_session_duration_minutes: int = 60

    # Scoring weights — must sum to 1.0
    weight_detection_rate: float = 0.25
    weight_mttd: float = 0.20
    weight_fp_rate: float = 0.10
    weight_containment: float = 0.10
    weight_report_quality: float = 0.15
    weight_coverage: float = 0.20

    # MITRE
    mitre_attack_version: str = "15.1"
    mitre_matrix: str = "enterprise"

    # Reports
    report_output_dir: str = "reports/output"
    report_templates_dir: str = "reports/templates"

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings
    ):
        """Priority, highest first: init kwargs, env vars, .env, config.yaml."""
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            _YamlSettingsSource(settings_cls),
            file_secret_settings,
        )


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------
@lru_cache()
def get_settings() -> Settings:
    """Return a cached Settings instance. Call once at startup.

    config.yaml is applied through settings_customise_sources, NOT as init
    kwargs — passing it here is what made it outrank the environment.
    """
    return Settings()

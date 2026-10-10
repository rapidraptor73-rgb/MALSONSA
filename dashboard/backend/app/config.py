from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Unified SIEM Dashboard API"
    api_prefix: str = "/api"
    database_url: str = "sqlite:///./siem_demo.db"
    cors_origins: str = "http://localhost:5173"

    wazuh_url: str = ""
    kibana_url: str = ""
    splunk_url: str = ""
    zabbix_url: str = ""
    prometheus_url: str = ""
    grafana_url: str = ""
    snort_url: str = ""
    suricata_url: str = ""
    pfsense_url: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

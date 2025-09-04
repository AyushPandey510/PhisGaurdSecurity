from pydantic import field_validator, ConfigDict
from pydantic_settings import BaseSettings
from typing import Optional, List
import os

class Settings(BaseSettings):
    """Application settings with validation"""

    # Flask settings
    debug: bool = False
    secret_key: str
    host: str = "0.0.0.0"
    port: int = 5000

    # API settings
    api_key: str

    # Security settings
    max_content_length: int = 1 * 1024 * 1024  # 1MB
    permanent_session_lifetime: int = 1800  # 30 minutes
    request_timeout: int = 30

    # CORS settings
    cors_origins_str: str = "chrome-extension://*,http://localhost:3000"

    # Rate limiting
    rate_limit_requests_per_minute: int = 60

    # External API keys
    google_safe_browsing_api_key: Optional[str] = None
    phishtank_api_key: Optional[str] = None
    hibp_api_key: Optional[str] = None
    leakcheck_api_key: str = "demo"

    # Logging
    log_level: str = "INFO"
    log_file: str = "phisguard.log"

    # SSL settings
    ssl_verify_certificates: bool = True
    max_redirects: int = 10

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False
    )

    @field_validator('secret_key')
    @classmethod
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError('Secret key must be at least 32 characters long')
        return v

    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v):
        if len(v) < 16:
            raise ValueError('API key must be at least 16 characters long')
        return v

    @field_validator('cors_origins_str', mode='before')
    @classmethod
    def validate_cors_origins_str(cls, v):
        if isinstance(v, str):
            # Split comma-separated string into list for validation
            origins = [origin.strip() for origin in v.split(',') if origin.strip()]
        else:
            origins = v

        for origin in origins:
            if not origin.startswith(('http://', 'https://', 'chrome-extension://')):
                raise ValueError(f'Invalid CORS origin: {origin}')
        return v  # Return the original string

    @property
    def cors_origins(self) -> List[str]:
        """Get CORS origins as a list"""
        return [origin.strip() for origin in self.cors_origins_str.split(',') if origin.strip()]

    @field_validator('log_level')
    @classmethod
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Invalid log level: {v}. Must be one of {valid_levels}')
        return v.upper()

# Global settings instance
settings = Settings()

def get_settings() -> Settings:
    """Get application settings"""
    return settings
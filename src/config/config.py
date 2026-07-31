import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """
    Centralized Configuration Module
    Manages environment variables, Supabase credentials, and application settings.
    """
    PROJECT_NAME: str = "PhishGuard Enterprise Email Phishing Analysis Platform"
    VERSION: str = "2.0.0"
    API_V1_PREFIX: str = "/api/v1"
    
    # Supabase Configuration
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "https://placeholder.supabase.co")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "placeholder_key")
    SUPABASE_JWT_SECRET: str = os.getenv("SUPABASE_JWT_SECRET", "placeholder_jwt_secret")
    
    # Security Configuration
    MAX_FILE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    ALLOWED_EXTENSIONS: list = [".eml", ".msg", ".txt", ".rfc822"]
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

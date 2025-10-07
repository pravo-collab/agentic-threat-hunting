"""Configuration settings for the threat hunting system."""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Settings:
    """Application settings."""
    
    # API Keys
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    LANGCHAIN_API_KEY: str = os.getenv("LANGCHAIN_API_KEY", "")
    
    # LangChain Configuration
    LANGCHAIN_TRACING_V2: str = os.getenv("LANGCHAIN_TRACING_V2", "true")
    LANGCHAIN_PROJECT: str = os.getenv("LANGCHAIN_PROJECT", "threat-hunting-ir")
    
    # Model Configuration
    DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "gpt-4o-mini")
    TEMPERATURE: float = float(os.getenv("TEMPERATURE", "0.1"))
    
    # System Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "10"))
    
    # Database Configuration
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./threat_hunting.db")
    
    # Redis Configuration
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    
    # Alert Thresholds
    ALERT_THRESHOLD_HIGH: int = int(os.getenv("ALERT_THRESHOLD_HIGH", "8"))
    ALERT_THRESHOLD_MEDIUM: int = int(os.getenv("ALERT_THRESHOLD_MEDIUM", "5"))
    ALERT_THRESHOLD_LOW: int = int(os.getenv("ALERT_THRESHOLD_LOW", "3"))
    
    # Response Configuration
    AUTO_RESPONSE_ENABLED: bool = os.getenv("AUTO_RESPONSE_ENABLED", "false").lower() == "true"
    REQUIRE_HUMAN_APPROVAL: bool = os.getenv("REQUIRE_HUMAN_APPROVAL", "true").lower() == "true"
    
    @classmethod
    def validate(cls) -> bool:
        """Validate required settings."""
        if not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required")
        return True


settings = Settings()

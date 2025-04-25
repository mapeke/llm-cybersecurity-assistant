import os
from pathlib import Path
from typing import Dict, Any, Optional
import json

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

# Ensure directories exist
for dir_path in [DATA_DIR, MODEL_DIR, LOGS_DIR, 
                DATA_DIR / "raw", DATA_DIR / "processed", DATA_DIR / "training",
                MODEL_DIR / "base_model", MODEL_DIR / "fine_tuned"]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Environment-specific settings
ENV = os.environ.get("ENVIRONMENT", "development")

# Default config
DEFAULT_CONFIG = {
    "development": {
        "debug": True,
        "log_level": "DEBUG",
        "llm": {
            "model_path": str(MODEL_DIR / "fine_tuned"),
            "base_model": "google/flan-t5-base",  # Example small model
            "max_length": 512,
            "temperature": 0.7
        },
        "api": {
            "host": "0.0.0.0",
            "port": 8000,
            "cors_origins": ["*"]
        },
        "integrations": {
            "wazuh": {
                "enabled": False,
                "api_url": "http://localhost:55000",
                "username": "wazuh",
                "password": ""  # Set via environment variable in production
            },
            "splunk": {
                "enabled": False,
                "api_url": "http://localhost:8089",
                "token": ""  # Set via environment variable in production
            }
        }
    },
    "production": {
        "debug": False,
        "log_level": "INFO",
        "llm": {
            "model_path": str(MODEL_DIR / "fine_tuned"),
            "base_model": "google/flan-t5-base",  # Would use larger model in actual production
            "max_length": 512,
            "temperature": 0.5
        },
        "api": {
            "host": "0.0.0.0",
            "port": int(os.environ.get("PORT", 8000)),
            "cors_origins": ["https://yourdomain.com"]  # Restrict in production
        },
        "integrations": {
            "wazuh": {
                "enabled": True,
                "api_url": os.environ.get("WAZUH_API_URL", ""),
                "username": os.environ.get("WAZUH_USERNAME", ""),
                "password": os.environ.get("WAZUH_PASSWORD", "")
            },
            "splunk": {
                "enabled": True,
                "api_url": os.environ.get("SPLUNK_API_URL", ""),
                "token": os.environ.get("SPLUNK_TOKEN", "")
            }
        }
    }
}

# Load custom config from file if exists
CONFIG_FILE = BASE_DIR / "config.json"
custom_config = {}
if CONFIG_FILE.exists():
    try:
        with open(CONFIG_FILE, "r") as f:
            custom_config = json.load(f)
    except json.JSONDecodeError:
        print(f"Warning: Config file {CONFIG_FILE} is not valid JSON. Using default configuration.")

# Deep merge function for configs
def deep_merge(source: Dict[str, Any], destination: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in source.items():
        if key in destination and isinstance(destination[key], dict) and isinstance(value, dict):
            deep_merge(value, destination[key])
        else:
            destination[key] = value
    return destination

# Create the final config by merging defaults with custom and environment variables
def get_config() -> Dict[str, Any]:
    env_config = DEFAULT_CONFIG.get(ENV, DEFAULT_CONFIG["development"])
    if ENV in custom_config:
        env_config = deep_merge(custom_config[ENV], env_config)
    return env_config

# Global config instance
config = get_config()

# Helper function to access config values with dot notation
def get_config_value(path: str, default: Optional[Any] = None) -> Any:
    """Get a config value using dot notation path (e.g., 'llm.temperature')"""
    parts = path.split('.')
    current = config
    
    for part in parts:
        if part not in current:
            return default
        current = current[part]
    
    return current
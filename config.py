import os
from pathlib import Path
import yaml
from dotenv import load_dotenv

# Load optional .env file
ENV_PATH = Path(__file__).resolve().parent / ".env"
if ENV_PATH.is_file():
    load_dotenv(dotenv_path=ENV_PATH)
else:
    load_dotenv()

# Load optional YAML configuration file if present (project root)
CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"
_yaml_cfg = {}
if CONFIG_PATH.is_file():
    try:
        with open(CONFIG_PATH, "r") as f:
            _yaml_cfg = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Failed to load config.yaml: {e}")

def _get(key: str, default=None):
    # Environment variables take precedence over yaml config
    return os.getenv(key, _yaml_cfg.get(key, default))

# Settings with sensible production/dev defaults
API_TOKEN = _get("API_TOKEN", "apex-operator-token-2026")
HOST = _get("HOST", "127.0.0.1")
PORT = int(_get("PORT", "8000"))
PACKET_QUEUE_SIZE = int(_get("PACKET_QUEUE_SIZE", "2000"))

# IDS thresholds (can be overridden via env or yaml)
PORT_SCAN_THRESHOLD = int(_get("PORT_SCAN_THRESHOLD", "15"))
PORT_SCAN_WINDOW = int(_get("PORT_SCAN_WINDOW", "10"))  # seconds
SYN_FLOOD_THRESHOLD = int(_get("SYN_FLOOD_THRESHOLD", "50"))
SYN_FLOOD_WINDOW = int(_get("SYN_FLOOD_WINDOW", "5"))
DNS_TUNNEL_LENGTH = int(_get("DNS_TUNNEL_LENGTH", "80"))

import os, tomllib
from pathlib import Path

from efcli import config

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")      / config.APP # fallback inmediato hardcodeado (en caso de, veah ;-;)
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME")     or Path.home() / ".local/share") / config.APP
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME")   or Path.home() / ".local/state") / config.APP

STATE_FILE = STATE_DIR / f"{config.APP}.json"
STATE_USERS_FILE = STATE_DIR / "usuarios.json"
DATA_PKI_DIR = DATA_DIR / "pki"
GLOBAL_CONFIG_FILE = CONFIG_DIR / "global.toml"
GLOBAL_CONFIG: dict = {}

def load_global():
    global GLOBAL_CONFIG
    with open(GLOBAL_CONFIG_FILE, "rb") as f:
        GLOBAL_CONFIG = tomllib.load(f)
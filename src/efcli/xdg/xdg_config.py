import os, tomllib, json
from pathlib import Path

from efcli import config

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")      / config.APP # fallback inmediato hardcodeado (en caso de, veah ;-;)
STATE_DIR  = Path(os.environ.get("XDG_STATE_HOME")  or Path.home() / ".local/state") / config.APP
DATA_DIR   = Path(os.environ.get("XDG_DATA_HOME")   or Path.home() / ".local/share") / config.APP

GLOBAL_CONFIG_FILE = CONFIG_DIR / f"{config.APP}_config.toml"
STATE_FILE         = STATE_DIR  / f"{config.APP}_state.json"
STATE_USERS_FILE   = STATE_DIR  / f"{config.APP}_users.json"
DATA_PKI_DIR       = DATA_DIR   / "pki"

GLOBAL_CONFIG: dict = {}

def load_global():
    global GLOBAL_CONFIG
    with open(GLOBAL_CONFIG_FILE, "rb") as f:
        GLOBAL_CONFIG = tomllib.load(f)

def load_state_file() -> dict:
    """
    Carga el JSON de estado desde el directorio de estado (XDG_STATE_HOME).
    Las funciones que llaman a ésta DEBEN confirmar entorno externo viable primero.
    """
    with open(STATE_FILE, "r") as f:
        return json.loads(s=f.read())

def load_state_users() -> dict:
    """
    Carga el JSON de usuarios desde el directorio de estado (XDG_STATE_HOME).
    Las funciones que llaman a ésta DEBEN confirmar entorno externo viable primero.
    """
    with open(STATE_USERS_FILE, "r") as f:
        return json.loads(s=f.read())

def load_principal_conf() -> dict:
    """
    Carga el TOML de configuración del usuario principal:
        (JSON de usuarios -> TOML del principal)

    Las funciones que llaman a ésta DEBEN confirmar entorno externo viable primero.
    """
    users = load_state_users()
    with open(users['usuarios'].get(users['principal'])['config_file'], "rb") as f:
        return tomllib.load(f)
import os, efcli, tomllib, json
from pathlib import Path

APP = "efcli"
VERSION = "0.1.0"

PACKAGE_DIR = Path(efcli.__file__).parent

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")      / APP # fallback inmediato hardcodeado (en caso de, veah ;-;)
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME")     or Path.home() / ".local/share") / APP
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME")   or Path.home() / ".local/state") / APP

STATE_FILE = STATE_DIR / f"{APP}.json"
STATE_USERS_FILE = STATE_DIR / "usuarios.json"

PKI_DEFAULTS = (
    PACKAGE_DIR / "assets" / "banxico_pki" / "banxico_root_bundle.pem",
    PACKAGE_DIR / "assets" / "banxico_pki" / "sat_intermedia_bundle.pem",
)

PKI_DIR = DATA_DIR / "pki"

GLOBAL_CONFIG_FILE = CONFIG_DIR / "global.toml"
GLOBAL_CONFIG: dict = {}

FLAGS = {
    'principal': {
        'flags_de_argumento': {
            'firmar': ('-f', '--firmar',),
            'perfil': ('-p', '--perfil',),
        },
        'flags_estaticas': {},

        'perfiles': {
            'B': 0,
            'L': 1,
            'T': 2,
            'A': 3,
        },

        'miscelanea': {
            'debug': ('-d', '--debug',),
            'quiet': ('-q', '--quiet',),
            'help': ('-h', '--help',),
            'version': ('-v', '--version',),
        },
    },

    'submodulos': {
        'init': {
            'flags_de_argumento': {},
            'flags_estaticas': {
                'reset': ('--reset',),
                'check': ('--check',),
            }
        },
        'ocsp': {
            'flags_de_argumento': {
                'query': ('--query',),
                'validez': ('--validez',),
                'parse': ('--parse',),
            },
            'flags_estaticas': {}
        },
        'tsa': {
            'flags_de_argumento': {
                'token': ('--token',),
            },
            'flags_estaticas': {}
        },
        'pdf': {
            'flags_de_argumento': {
                'firmas': ('--firmas',),
            },
            'flags_estaticas': {}
        },
        'user': {
            'flags_de_argumento': {},
            'flags_estaticas': {
                'whoami': ('--whoami',),
            }
        },
    },
}

MENSAJES_MISC = {
    "banner": f"""
                ▄▄▄▄                                                                      
              ▄█▀ ▀▀  ██                                           ▄▄█▀▀▀█▄  █████▀      ▀████▀ 
              ██▀                                                ▄██▀     ▀█   ██          ██   
  ▄▄█▀██     █████  ▀████▀ ███▄███ ▀████████▄█████▄   ▄█▀██▄     ██▀       ▀   ██          ██   
 ▄█▀   ██     ██      ██    ██▀ ▀▀   ██    ██    ██  ██   ██     ██            ██          ██   
 ██▀▀▀▀▀▀     ██      ██    ██       ██    ██    ██   ▄█████     ██▄           ██          ██   
 ██▄     ▄▄   ██      ██    ██       ██    ██    ██  ██   ██     ▀██▄     ▄▀   ██    ▄█    ██   
  ▀█████ ▀▀ █████▄  ▄████▄ ████▄   ▄████  ████  ████▄ ████▀██▄     ▀▀█████▀  █████████▀ ▄██████▄

                                                v{VERSION}
""",

    'help': f"""e.firma CLI {VERSION}, Solución de firma digital PAdES para la PKI del Banco de México.

Uso principal:

    efcli                           (sin opciones: firma con la configuración del usuario actual)
    efcli -f FILE [opciones] ...    (con opciones: firma con sobreescritura temporal de config para las opciones explicitas)

Uso de submodulos:

    efcli init [opciones] ...
    efcli ocsp [opciones] ...
    efcli tsa  [opciones] ...
    efcli pdf  [opciones] ...
    efcli user [opciones] ...

Firma:

  -f,  --firmar FILE|DIR    Ruta de archivo .pdf o directorio que almacene archivos .pdf (opcional).
  -p,  --perfil OPT         Perfil de firma en *mayus/minus*: 'B', 'L', 'T', 'A' (opcional).

Submodulo INIT:

  init                      Inicialización: Entorno externo, rutas XDG, perfiles, config. Usar tras instalación o reset.
  init --reset              Eliminación completa del entorno externo. Usar antes de desinstalar o reconfigurar con 'init'.
  init --check              Comprobación de integridad del entorno externo.

Submodulo OCSP:

  ocsp --query CERT         Nueva consulta OCSP para 'CERT' con el responder por defecto.
  ocsp --validez RESP       Imprimir el estado de un x509 (good, revoked) desde una respuesta OCSP (DER o PEM).
  ocsp --parse RESP         Imprimir en texto legible una respuesta OCSP completa (DER o PEM).

Submodulo TSA:

  tsa --token PDF           Añadir un Timestamp Token (TST) incremental a un PDF usando la TSA por defecto.

Submodulo PDF:

  pdf --firmas PDF          Imprimir el historial de firmas de un PDF.

Miscelánea:

  -d,  --debug              Muestra información más detallada sobre el proceso.
  -q,  --quiet              Limita la salida solo a resultados.

  -h,  --help               Imprime éste menú de ayuda.
  -v,  --version            Imprimir la versión actual.
""",

    "msj_desfase_temporal": """ATENCION.

Garantizar un perfil robusto de validación para una firma digital es un proceso sensible
a desfases de tiempo!, especialmente para el perfil 'Long-Term (L)'.

Hasta el momento no se ha contactado con ninguna entidad de validación externa de la
cual depende éste perfil, únicamente se ha cargado el contexto y material criptográfico
necesario para continuar con el proceso de firma que si DEPENDE de coordinación temporal.""",

    "disclaimer_firmas_separadas": """Al firmar bajo esquema PAdES el contenedor de firma CMS/PKCS#7 generado se incrusta en el PDF resultante,
por lo que cada documento firmado ya actua como elemento único para su uso práctico: transporte, lectura
y validación de firma completa.

Esta herramienta añade un comportamiento complementario a la firma base: la creación de copias fisicamente
separadas de los contenidos criptográficos más relevantes de cada PDF firmado, contenedores CMS/PKCS#7 de
firmante y Timestamp Tokens (TST) de TSA y su almancenado en éste directorio.

Esto tiene como proposito proveer de manera aislada una copia integra de cada artefacto de firma PAdES
generado en cada sesión de firma para fines de auditoría criptográfica y del contenido mismo de las firmas.

	- Auditar algoritmos usados para cumplimiento normativo: hashes, cifrado, OIDs.
	- Comprobar atributos firmados: signingTime, messageDigest, políticas de firma.
	- Inspeccionar la cadena de certificados incrustada en los CMS.
	- Si existiesen, auditar y validar TSTs de forma independiente contra la TSA.

Los elementos aquí presentes no son suficientes por si solos para validar una firma digital realizada
en este contexto (y tampoco se prentende que se utilicen para ello). La validación real en la práctica
la realiza su software de validación preferido: Adobe Acrobat Reader, VeraPDF, pyhanko cli, etc. usando
solo el PDF resultante después de firmar, por lo que si usted no requiere ni necesita inspeccionar estos
artefactos separados simplemente puede ignorarlos o borrarlos.
""",
}

def load_global():
    global GLOBAL_CONFIG

    with open(GLOBAL_CONFIG_FILE, "rb") as f:
        GLOBAL_CONFIG = tomllib.load(f)

def load_current_user():
    with open(STATE_USERS_FILE, "r") as f:
        usuarios = json.loads(s=f.read())

    principal_cnf = usuarios['usuarios'].get(usuarios['principal'])['config_file']
    with open(principal_cnf, "rb") as f:
        cnf = tomllib.load(f)
    return cnf
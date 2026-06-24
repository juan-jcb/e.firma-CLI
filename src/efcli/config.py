import efcli
from pathlib import Path

APP = "efcli"
VERSION = "0.1.0"

PACKAGE_DIR = Path(efcli.__file__).parent
PKI_ASSETS = (
    PACKAGE_DIR / "assets" / "banxico_pki" / "banxico_root_bundle.pem",
    PACKAGE_DIR / "assets" / "banxico_pki" / "sat_intermedia_bundle.pem",
)

# Flags estáticas se evaluan en conmutador, las de argumento en sintaxis post-conmutador.
# Se mantiene la estructura en este diccionario por estetica visual.
FLAGS = {
    'principal': {
        'flags_de_argumento': {
            'firmar': ('-f', '--firmar',),
            'perfil': ('-p', '--perfil',),
        },

        'perfiles': {
            'B': 0,
            'L': 1,
            'T': 2,
            'A': 3,
        },
    },

    'submodulos': {
        'init': {
            #'flags_de_argumento': {},
            'flags_estaticas': {
                'reset': ('--reset',),
                'check': ('--check',),
            }
        },
        'user': {
            #'flags_de_argumento': {},
            'flags_estaticas': {
                'whoami': ('--whoami',),
                'conf': ('--conf',),
                'raw_conf': ('--raw-conf',),
            }
        },

        'ocsp': {
            'flags_de_argumento': {
                'request': ('--request',),
                'validez': ('--validez',),
                'parse': ('--parse',),
            },
            'flags_estaticas': {
                'request': ('--request',),
            }
            
        },
        'tsa': {
            'flags_de_argumento': {
                'token': ('--token',),
            },
            #'flags_estaticas': {}
        },
        'pdf': {
            'flags_de_argumento': {
                'firmas': ('--firmas',),
            },
            #'flags_estaticas': {}
        },
    },

    'miscelanea': {
        'debug': ('-d', '--debug',),
        'quiet': ('-q', '--quiet',),
        'help': ('-h', '--help',),
        'version': ('-v', '--version',),
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

Uso principal (con entorno válido):

    efcli                           (sin opciones) Firma cualquier .pdf en el directorio de firmas con la configuración del usuario principal.
    efcli -f FILE [opciones] ...    (con opciones) Firma con sobreescritura temporal de configuración para las opciones explicitas.

Uso de submodulos:

    efcli init [opciones] ...
    efcli user [opciones] ...
    efcli ocsp [opciones] ...
    efcli tsa  [opciones] ...
    efcli pdf  [opciones] ...

Firma (opciones explicitas) (no disponible aún):

  -f,  --firmar FILE|DIR    Ruta de archivo .pdf o directorio que almacene archivos .pdf (opcional).
  -p,  --perfil OPT         Perfil de firma en *mayus/minus*: 'B', 'L', 'T', 'A' (opcional).

Submodulo INIT:

  init                      Inicialización: Entorno externo, rutas XDG, perfiles, config. Usar tras instalación o reset.
  init --reset              Eliminación completa del entorno externo. Usar antes de desinstalar o para reconfigurar con 'init'.
  init --check              Comprobación de integridad del entorno externo.

Submodulo USER:

  user --add                Añadir un nuevo usuario local (prompt interactivo).
  user --del                Borrar un usuario local (prompt interactivo).
  user --change             Cambiar de usuario principal (prompt interactivo).

  user --whoami             Imprime el nombre del usuario principal y su certificado X.509 asoociado.
  user --list               Imprime listado con todos los usuarios del programa.
  user --conf               Imprime la configuración del usuario principal simplificada.
  user --toml               Imprime la configuración del usuario principal en su formato original TOML.

Submodulo OCSP:

  ocsp --request CERT       (con argumento) Nueva consulta OCSP para 'CERT' usando el responder por defecto.
  ocsp --request            (sin argumento) Nueva consulta OCSP para el certificado del usuario principal usando el responder por defecto.
  ocsp --validez RESP       Imprimir el estado de un x509 (good, revoked) desde una respuesta OCSP (DER o PEM).
  ocsp --parse RESP         Imprimir en texto legible una respuesta OCSP completa (DER o PEM).

Submodulo TSA (no disponible aún):

  tsa --token PDF           Añadir un Timestamp Token (TST) incremental a un PDF usando la TSA por defecto.

Submodulo PDF (no disponible aún):

  pdf --firmas PDF          Imprimir el historial de firmas de un PDF.

Miscelánea:

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

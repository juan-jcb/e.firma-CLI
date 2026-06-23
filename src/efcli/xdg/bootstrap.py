import logging, shutil, json, tomllib
from pathlib import Path

from efcli import config
from efcli.utils import registros, wrappers
from efcli.xdg import usuarios, mensajes

logger = logging.getLogger(__name__)

MAIN_ENV_DIRS = (config.CONFIG_DIR, config.DATA_DIR, config.STATE_DIR) # GLOBAL_CONFIG_FILE['pdf_ruta_base']

def check_env(log_level=logging.INFO):
    '''
    Evaluación en 2 partes sobre la integridad del entorno externo XDG.

        1. Qué los directorios de entorno existan
        2. Qué la configuración de estádo sea coherente.
    '''
    with registros.modded_logs(target_logger=logger, level=log_level):

        logger.debug('=== ESTRUCTURA XDG ===')
        for i in MAIN_ENV_DIRS:
            if Path(i).exists():
                logger.debug("Existe: '%s'", i)
            else:
                logger.debug("El directorio '%s' no existe.", i)
                return False

        logger.debug('=== ARCHIVOS DE ESTADO ===')
        if Path(config.STATE_FILE).exists() and Path(config.STATE_USERS_FILE).exists():
            logger.debug("Existe: '%s'", config.STATE_FILE)
            logger.debug("Existe: '%s'", config.STATE_USERS_FILE)


            logger.debug("=== COHERENCIA DEL ENTORNO ===")
            with open(config.STATE_FILE, "r") as f:
                programa = json.loads(s=f.read())

            for d in programa['xdg_dirs'].values():
                if Path(d).is_dir():
                    logger.debug("Correctamente referenciado: '%s'", d)
                else:
                    logger.debug("El directorio '%s' no fue encontrado.", d)
                    return False

            for d in programa['custom_dirs'].values():
                if Path(d).is_dir():
                    logger.debug("Existe: '%s'", d)
                else:
                    logger.debug("El directorio '%s' no fue encontrado.", d)
                    return False

            for f in programa['assets']:
                if Path(f).is_file():
                    logger.debug("Existe: '%s'", f)
                else:
                    logger.debug("El archivo '%s' no fue encontrado.", f)
                    return False
                
            logger.debug("=== USUARIOS ===")
            with open(config.STATE_USERS_FILE, "r") as f:
                usuarios = json.loads(s=f.read())

            logger.debug("Principal: %s", usuarios['principal'])
            for idx, i in enumerate(iterable=usuarios['usuarios'].keys(), start=1):
                logger.debug("%s: %s", idx, i)
                for v, k in usuarios['usuarios'][i].items(): # porque son diccionarios
                    if not Path(k).exists():
                        logger.debug("[%s] '%s' no fue encontrado.", i , k)
                        return False
                    logger.debug("   %s: '%s'", v, k)

        else:
            logger.debug("Faltan archivos de estado.")
            return False

        return True

@wrappers.salida_limpia()
@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def reset_env():
    with open(config.GLOBAL_CONFIG_FILE, "rb") as f:
        global_config = tomllib.load(f)

    logger.warning("Esta acción eliminará los directorios del entorno externo con todo su contenido!!")
    logger.warning("Si realmente lo desea borrar asegurese antes de respaldar cualquier archivo importante:\n")
    print(f"  1. Claves y certificados en: '{config.CONFIG_DIR}'")
    print(f"  2. Documentos guardados en:  '{global_config['pdf_ruta_base']}'")
    while True:
        opcion = input('\n¿Eliminar entorno externo? (y/n): ')
        if opcion == 'y':
            print('Eliminando...\n')
            break
        elif opcion == 'n':
            print('Saliendo...')
            return False
        else:
            print('Ingrese una opción correcta.')

    for i in (*(MAIN_ENV_DIRS), global_config['pdf_ruta_base']):
        try:
            shutil.rmtree(i)
            logger.info("Borrado: '%s'", i)

        except FileNotFoundError:
            logger.error("El directorio no existe: '%s'", i)
        except PermissionError:
            logger.error("Sin permisos para eliminar: '%s'", i)
        except Exception as e:
            logger.error("%s", e)

    logger.info("Entorno externo borrado completamente. (inicie uno nuevamente con 'efcli init')")
    return True

@wrappers.salida_limpia()
@wrappers.eval(fn_condicion=check_env, si_false="Ya existe un entorno válido! (si quiere revisarlo: 'efcli init --check')")
def init():
    import time
    print("CONFIGURACIÓN INICIAL.\n")
    
    # 1. Directorio de firmas
    print(mensajes.mensajes_init['directorio_firmas'])
    while True:
        home_depth = Path.home().parts
        flag = False
        _ = input("Directorio para firmas ($HOME/): ")
        test_depth = (Path.home() / _).parts
        if len(test_depth) - 2 == len(home_depth) - 1: # total -2 porque se le saca la / y el nivel actual (cualquier otra cosa no está al mismo nivel)
            if (Path.home() / _).exists():
                logger.warning("Ese directorio ya existe!, por favor ingrese uno nuevo.")
                continue
            for i in range(len(home_depth)):
                if test_depth[i] != home_depth[i]:
                    logger.warning("La ruta ingresada no pertenece a $HOME!, por favor ingrese uno nuevo.")
                    flag = True
                    break
            if flag:
                continue
            else:
                PDF_RUTA_BASE = Path.home() / _
                break
        else:
            logger.warning("El directorio debe estár al mismo nivel que su $HOME, por favor ingrese uno nuevo.")
    time.sleep(1)
    print("\033[H\033[2J", end="")

    new_user = usuarios.new_user(mensajes=mensajes.mensajes_init, es_init=True)
    NOMBRE_USUARIO, CERT_USUARIO, PKEY_USUARIO, ID_FIRMA, NOMBRE_FIRMANTE, RAZON, LUGAR, CONTACTO = new_user['main_values']
    USER_DIR, USER_CONFIG_FILE, cert_input, pkey_input = new_user['extra']
    SKEL_USER = new_user['skel']

    # Con la declaración explcita de los certificados de una PKI se deja de ser dependiente solo al conetxto
    # de la PKI de banxico y se puede operar con cualquier otra siempre que se tengan sus x509 organizados.
    SKEL_GLOBAL = f'''# Configuración global de e.firma CLI.

pdf_ruta_base = "{PDF_RUTA_BASE}"

[PKI]
trust_roots = "{config.DATA_PKI_DIR / 'banxico_root_bundle.pem'}"
intermediate_cas = "{config.DATA_PKI_DIR / 'sat_intermedia_bundle.pem'}"

[OCSP]
endpoints = [
    "https://cfdi.sat.gob.mx/edofiel",
    "https://www.sat.gob.mx/ocsp"
]
# el X509 del responder curiosamente si tiene extensión AIA: OCSP - URI:http://www.sat.gob.mx/ocsp

[TSA]
CMS_URI = "https://freetsa.org/tsr"
CMS_HASH = "sha384"

DSS_URI = "https://freetsa.org/tsr"
DSS_HASH = "sha384"
'''

    # Estructura lógica del entorno externo tras init()
    init_state_programa = {
            'xdg_dirs': {
                'config_dir': config.CONFIG_DIR.as_posix(),
                'data_dir': config.DATA_DIR.as_posix(),
                'state_dir': config.STATE_DIR.as_posix(),
            },

            'custom_dirs': {
                'pdf_ruta_base': PDF_RUTA_BASE.as_posix(),
                'data_pki_dir': config.DATA_PKI_DIR.as_posix(),
            },

            'assets': [f"{config.DATA_PKI_DIR}/{i.name}" for i in config.PKI_ASSETS]
        }

    init_state_usuarios = {
            'principal': NOMBRE_USUARIO,
            'usuarios': {
                NOMBRE_USUARIO: {
                    'user_dir': USER_DIR.as_posix(),
                    'config_file': USER_CONFIG_FILE.as_posix(),
                    'cert': CERT_USUARIO.as_posix(),
                    'pkey': PKEY_USUARIO.as_posix(),
                },
            }
        }

    # Poblado de archivos del entorno externo.
    for i in (*(MAIN_ENV_DIRS), config.DATA_PKI_DIR, USER_DIR, PDF_RUTA_BASE):
        i.mkdir(parents=True, exist_ok=True)
    with open(config.GLOBAL_CONFIG_FILE, "w") as f: 
        f.write(SKEL_GLOBAL)
    with open(USER_CONFIG_FILE, "w") as f: 
        f.write(SKEL_USER)
    shutil.copy2(src=cert_input, dst=CERT_USUARIO)
    shutil.copy2(src=pkey_input, dst=PKEY_USUARIO)
    for i in config.PKI_ASSETS:
        shutil.copy2(src=i, dst=f"{config.DATA_PKI_DIR}/{i.name}")
    state_programa = json.dumps(obj=init_state_programa, indent=2, ensure_ascii=False)
    state_usuarios = json.dumps(obj=init_state_usuarios, indent=2, ensure_ascii=False)
    with open(config.STATE_FILE, "w") as f:
        f.write(state_programa)
    with open(config.STATE_USERS_FILE, "w") as f:
        f.write(state_usuarios)

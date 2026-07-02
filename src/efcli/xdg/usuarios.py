import logging, tomllib, json, time, sys
from pathlib import Path

from .xdg_config import STATE_USERS_FILE, CONFIG_DIR
from efcli.core import registros, wrappers, regex, x509, pkey

from . import mensajes
from .bootstrap import check_env

logger = logging.getLogger(__name__)

def load_state_users() -> dict:
    with open(STATE_USERS_FILE, "r") as f:
        return json.loads(s=f.read())

def load_current_user_conf():
    # Carga archivo de usuarios (el toml del usuario referenciado en el archivo de estado)
    users = load_state_users()
    with open(users['usuarios'].get(users['principal'])['config_file'], "rb") as f:
        return tomllib.load(f)

def new_user(mensajes: dict, es_init: bool = False):
    # 1. Directorio de firmas (se muestra en init(), aunque técnicamente esté disponible aquí.)

    # 2. nombre de usuario
    print(mensajes['usuario_local'])
    if not es_init:
        users = load_state_users()

        # 1. Evaluar que no existan más de 10 usuarios, así es, limite arbitrario ;-; (por qué se usarian más de 10 perfiles?¿)
        # TODO: cambiar el limite si es necesario.
        if len(users['usuarios']) > 10:
            logger.warning("El limite máximo de usuarios es de 10. sorwy (╥﹏╥)")
            return False

        # 2. Evaluar que no existan nombres repetidos
        while True:
            NOMBRE_USUARIO = regex.input_regex(patron=regex.ASCII_SIMPLE, mensaje="Nombre de usuario local: ", pista="Alfanumerico mayus/minus, guiones medio, bajo, puntos y espacios intermedios.")
            # TODO: en una base de datos real esto sería malardo, pero de momento no contemplo más de 10 entradas en JSON para usuarios.
            if not NOMBRE_USUARIO in (i for i in users['usuarios']):
                break
            logger.warning("El usuario ingresado YA EXISTE. Ingrese uno diferente!")

    else:
        # TODO: debería manejar los nombres de usuario solo mayus o solo minus¿?¿?¿? o permitir usuario distinto de mismo nombre con variación por mayus/minus
        NOMBRE_USUARIO = regex.input_regex(patron=regex.ASCII_SIMPLE, mensaje="Nombre de usuario local: ", pista="Alfanumerico mayus/minus, guiones medio, bajo y puntos.")
    time.sleep(1)
    sys.stdout.write("\033[H\033[2J")

    USER_DIR = CONFIG_DIR / NOMBRE_USUARIO
    USER_CONFIG_FILE = USER_DIR / f"{NOMBRE_USUARIO}.toml"

    # 3. archivos de e.firma
    # TODO: confirmar que el cert ingresado pertenezca a la PKI de Banxico. si no, salir con mensaje informativo
    # TODO: confirmar que la clave pública del x509 y la clave pública derivada de la privada coincidan mediante fingreprint para establecer relación del material criptográfico
    print(mensajes['archivos_efirma'])
    while True:
        cert_input = Path(input("Ruta absoluta del certificado del firmante (.cer): "))
        if cert_input.is_file():
            try:
                crt, encode = x509.cargar_cert_asn1(cert=cert_input)
            except Exception:
                logger.warning("El archivo ingresado no es un certificado. Ingreselo nuevamente.")
                continue
            else:
                print(f"Correcto. {x509.leer_subject_simple(crt)} ({encode})")
                CERT_USUARIO = USER_DIR / f"{NOMBRE_USUARIO}.crt"
                break
        else:
            logger.warning("La ruta es incorrecta, ingresela de nuevo!")
            continue

    while True:
        pkey_input = Path(input("Ruta absoluta de la clave privada del firmante (.key): "))
        if pkey_input.is_file():
            try:
                cifrada, encode = pkey.es_pkey_cifrada(pkey=pkey_input)
            except Exception:
                logger.warning("El archivo ingresado no es una clave privada. Ingresela nuevamente.")
                continue
            else:
                if cifrada:
                    print(f"Correcto. Clave privada cifrada ({encode})")
                else:
                    print(f"Correcto. Clave privada SIN cifrado ({encode})")
                
                PKEY_USUARIO = USER_DIR / f"{NOMBRE_USUARIO}.key"
                break
        else:
            logger.warning("La ruta es incorrecta, ingresela de nuevo!")
    time.sleep(1)
    sys.stdout.write("\033[H\033[2J")

    # 4. metadatos de firma
    print(mensajes['metadatos_firma'])
    ID_FIRMA        = regex.input_regex(patron=regex.ALFANUMERICO, mensaje="Identificador de la firma: ", pista="Alfanumerico mayus/minus.")
    NOMBRE_FIRMANTE = regex.input_regex(patron=regex.SPANISH, mensaje="Nombre del firmante: ", pista="Solo caracteres del alfabeto en español.")
    RAZON           = regex.input_regex(patron=regex.SPANISH, mensaje="Razón de firma: ", pista="Solo caracteres del alfabeto en español.")
    LUGAR           = regex.input_regex(patron=regex.SPANISH, mensaje="Lugar de firma: ", pista="Solo caracteres del alfabeto en español.")
    CONTACTO        = regex.input_regex(patron=regex.CORREOS, mensaje="Correo del firmante: ", pista="Solo correos electrónicos.")
    time.sleep(1)
    sys.stdout.write("\033[H\033[2J")

    # 5. preferencias sobre el perfil de firma
    print(mensajes['pefiles_firma'])
    USAR_OCSP    = regex.input_regex(patron=regex.SI_NO, mensaje="¿Usar validación OCSP? (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_CMS = regex.input_regex(patron=regex.SI_NO, mensaje="¿Usar sello de tiempo TST en su contenedor firma? (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_DSS = regex.input_regex(patron=regex.SI_NO, mensaje="¿Usar sello de tiempo TST en PDF (/DocTimeStamp)? (y/n): ", pista='Solo letras "y", "n".')
    opciones = [f"{i == 'y'}".lower() for i in [USAR_OCSP, USAR_TSA_CMS, USAR_TSA_DSS]] # me parace cutre, pero eh, deja en minisculas un mapeo de booleanos para usar toml

    # #!. skeleton de usuario
    SKEL_USER = f'''# Configuración de usuario {NOMBRE_USUARIO}

[firmante]
certificado = "{CERT_USUARIO}"
clave_privada = "{PKEY_USUARIO}"

[metadatos_firma]
nombre_firma = "{ID_FIRMA}"
nombre_firmante = "{NOMBRE_FIRMANTE}"
razon = "{RAZON}"
lugar = "{LUGAR}"
contacto = "{CONTACTO}"

[firma_visible]
usar = false

# Página donde mostrar el campo visual de la firma.
pagina = 0

# Dimensiones
ancho = 200
alto = 50

# Posición en X e Y
coords_x = 200
coords_y = 85
    
[preferencias]
# validación externa sobre el x509 del firmante con OCSP (Eleva de Perfil B a Pefil L)
OCSP = {opciones[0]}

# TST en el CMS del firmante (Añade Perfil T)
TST_CMS = {opciones[1]}

# TST en /DocTimeStamp del PDF (Añade Perfil A)
TST_DSS = {opciones[2]}

# Según el flujo de operaciones PAdES, la configuración de una TSA para timestamping en DSS NO debería
# estár en éste dirccionario, sin embargo un firmante individual, dado que es el único participante
# tiene poder de desición completo sobre si quiere utilizar TSTs incrementales o no en el /DocTimeStamp
# de los PDFs que firma, por lo que la configuración de una TSA para este proposito adquiere indirectamente
# el caracter de "metadatos de firma del firmante" y se prefiere en este diccionario (aunque técnicamente
# no pertenezca a los metadatos "reales" de su firma).
    
# Caso contrario en firma múltiple de 2 o más: todos los firmantes deben firmar primero y acordar si al
# final de la sesión de firma se añade el TST incremental sobre lo firmado; haciendola una decisión
# concensual y en consecuencia desacoplada a los metadatos de firma de cada participante (como en principio
# debe de ser).
'''

    return {
        "main_values": (
            NOMBRE_USUARIO,                                     # 2. nombre de usuario
            CERT_USUARIO, PKEY_USUARIO,                         # 3. archivos de e.firma
            ID_FIRMA, NOMBRE_FIRMANTE, RAZON, LUGAR, CONTACTO   # 4. metadatos de firma
        ),
        "extra": (
            USER_DIR,
            USER_CONFIG_FILE,
            cert_input,
            pkey_input,
        ),
        "skel": SKEL_USER
    }

@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def list_users():
    logger.info("=== USUARIOS ===")
    with open(STATE_USERS_FILE, "r") as f:
        usuarios = json.loads(s=f.read())

    logger.info("Principal: %s", usuarios['principal'])
    for idx, i in enumerate(iterable=usuarios['usuarios'].keys(), start=1):
        logger.info("%s: %s", idx, i)
        for v, k in usuarios['usuarios'][i].items(): # porque son diccionarios
            if not Path(k).exists():
                logger.info("[%s] '%s' no fue encontrado.", i , k)
                return False
            logger.info("   %s: '%s'", v, k)

@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def print_current_user():
    users = load_state_users()
    principal_name = users.get('principal')
    principal_dict = users['usuarios'].get(users['principal'])
    cert_path = principal_dict['cert']
    with open(cert_path, "rb") as f:
        cert, _ = x509.cargar_cert_asn1(cert=f.read())

    with registros.modded_logs(target_logger=logger, level=logging.DEBUG):
        logger.debug("Usuario: %s", principal_name)
        logger.debug("e.firma: %s", x509.leer_subject_simple(cert))

@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def print_current_user_conf():
    users = load_state_users()
    principal_name = users.get('principal')
    principal_dict = users['usuarios'].get(users['principal'])
    cert_path = principal_dict['cert']

    with open(users['usuarios'].get(users['principal'])['config_file'], "rb") as f:
        cnf = tomllib.load(f)
    with open(cert_path, "rb") as f:
        cert, _ = x509.cargar_cert_asn1(cert=f.read())

    with registros.modded_logs(target_logger=logger, level=logging.DEBUG):
        logger.debug("CONFIGURACIÓN DE USUARIO: '%s'", principal_name)
        logger.debug("=== E.FIRMA ===", )
        logger.debug("Propietario: %s", x509.leer_subject_simple(cert))
        logger.debug("Certificado: '%s'", cnf['firmante']['certificado'])
        logger.debug("Clave privada: '%s'", cnf['firmante']['clave_privada'])
        logger.debug("=== METADATOS DE FIRMA ===", )
        logger.debug("Identificador: '%s'", cnf['metadatos_firma']['nombre_firma'])
        logger.debug("Firmante: '%s'", cnf['metadatos_firma']['nombre_firmante'])
        logger.debug("Razón: '%s'", cnf['metadatos_firma']['razon'])
        logger.debug("Lugar: '%s'", cnf['metadatos_firma']['lugar'])
        logger.debug("Correo: '%s'", cnf['metadatos_firma']['contacto'])
        logger.debug("=== CAMPO VISIBLE DE FIRMA ===", )
        logger.debug("Usar firma visible: %s", cnf['firma_visible']['usar'])
        logger.debug("Página: %s", cnf['firma_visible']['pagina'])
        logger.debug("Ancho: %s", cnf['firma_visible']['ancho'])
        logger.debug("Alto: %s", cnf['firma_visible']['alto'])
        logger.debug("Coordenadas en X: %s", cnf['firma_visible']['coords_x'])
        logger.debug("Coordenadas en Y: %s", cnf['firma_visible']['coords_y'])
        logger.debug("=== PREFERENCIAS DE FIRMA ===", )
        logger.debug("Validación OCSP (L): %s", cnf['preferencias']['OCSP'])
        logger.debug("Sello de tiempo en firma (T): %s", cnf['preferencias']['TST_CMS'])
        logger.debug("Sello de tiempo en PDF (A): %s", cnf['preferencias']['TST_DSS'])

@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def print_current_user_toml():
    users = load_state_users()
    with open(users['usuarios'].get(users['principal'])['config_file'], "r") as f:
        print(f.read())

@wrappers.salida_limpia()
@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def add_user():
    # Para añadir un usuario se asume entorno viable (validado en conmutador)
    nuevo = new_user(mensajes=mensajes.mensajes_adduser, es_init=False)
    if nuevo:
        import shutil
        users = load_state_users()

        NOMBRE_USUARIO, CERT_USUARIO, PKEY_USUARIO, ID_FIRMA, NOMBRE_FIRMANTE, RAZON, LUGAR, CONTACTO = nuevo['main_values']
        USER_DIR, USER_CONFIG_FILE, cert_input, pkey_input = nuevo['extra']
        SKEL_USER = nuevo['skel']

        users['usuarios'][NOMBRE_USUARIO] = {
            'user_dir': USER_DIR.as_posix(),
            'config_file': USER_CONFIG_FILE.as_posix(),
            'cert': CERT_USUARIO.as_posix(),
            'pkey': PKEY_USUARIO.as_posix(),
        }
        updated_users = json.dumps(obj=users, indent=2, ensure_ascii=False)

        # Poblado de archivos de nuevo usuario (en entorno ya viable)
        USER_DIR.mkdir(parents=True, exist_ok=True)
        with open(USER_CONFIG_FILE, "w") as f: 
            f.write(SKEL_USER)
        shutil.copy2(src=cert_input, dst=CERT_USUARIO)
        shutil.copy2(src=pkey_input, dst=PKEY_USUARIO)
        with open(STATE_USERS_FILE, "w") as f:
            f.write(updated_users)

        logger.info("Usuario '%s' creado correctamente!", NOMBRE_USUARIO)

@wrappers.salida_limpia()
@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def del_user():
    users = load_state_users()

    logger.info("=== Usuarios Actuales ===")
    logger.info("Principal: %s", users['principal'])
    for idx, i in enumerate(iterable=users['usuarios'].keys(), start=1):
        logger.info("%s: %s", idx, i)

    if len(users['usuarios']) == 1:
        logger.error("No puede borrar usuarios habiendo solo 1 (ㆆ_ㆆ) Saliendo...")
        return False

    print()
    while True:
        opcion = int(regex.input_regex(patron=regex.NUMERICO, mensaje="Ingrese el n° de usuario que desea borrar: ", pista="Solo números naturales positivos."))
        if opcion == 0 or opcion > idx: # idx es lo mismo que len() sobre los usuarios
            logger.warning("No existe un usuario con ese número. Vuelva a ingresarlo.")
        else:
            seleccionado = list(users['usuarios'].keys())[opcion - 1] # -1 por el start en enumerate
            if seleccionado == users['principal']:
                logger.warning("No puede eliminar al usuario principal! (si lo quiere borrar cambie antes de principal)")
                continue
            break

    logger.info("Ha seleccionado al usuario '%s'", seleccionado) 
    print()
    while True:
        confirmar = input('¿Desea borrarlo? (y/n): ')
        if confirmar == 'y':
            print('Borrando...')
            break
        elif confirmar == 'n':
            print('Saliendo...')
            return False
        else:
            print('Ingrese una opción correcta.')

    try:
        import shutil
        shutil.rmtree(users['usuarios'][seleccionado]['user_dir'])
    except FileNotFoundError:
        logger.error("El directorio no existe: '%s'", i)
        return False
    except PermissionError:
        logger.error("Sin permisos para eliminar: '%s'", i)
        return False
    except Exception as e:
        logger.error("%s", e)
        return False
    else:
        del(users['usuarios'][seleccionado])
        updated_users = json.dumps(obj=users, indent=2, ensure_ascii=False)
        with open(STATE_USERS_FILE, "w") as f:
            f.write(updated_users)

        logger.info("Usuario '%s' borrado correctamente!", seleccionado)
        return True

@wrappers.salida_limpia()
@wrappers.eval(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def change_user():
    users = load_state_users()

    logger.info("=== Usuarios Actuales ===")
    logger.info("Principal: %s", users['principal'])
    for idx, i in enumerate(iterable=users['usuarios'].keys(), start=1):
        logger.info("%s: %s", idx, i)

    if len(users['usuarios']) == 1:
        logger.error("No puede cambiar de usuario habiendo solo 1 (ㆆ_ㆆ) Saliendo...")
        return False

    print()
    while True:
        opcion = int(regex.input_regex(patron=regex.NUMERICO, mensaje="Ingrese el n° de usuario al que desea cambiar: ", pista="Solo números naturales positivos."))
        if opcion == 0 or opcion > idx: # idx es lo mismo que len() sobre los usuarios
            logger.warning("No existe un usuario con ese número. Vuelva a ingresarlo.")
        else:
            seleccionado = list(users['usuarios'].keys())[opcion - 1] # -1 por el start en enumerate
            if seleccionado == users['principal']:
                logger.warning("Ese usuario ya es el principal!!")
                continue
            break

    users['principal'] = seleccionado
    updated_users = json.dumps(obj=users, indent=2, ensure_ascii=False)
    with open(STATE_USERS_FILE, "w") as f:
        f.write(updated_users)

    print()
    logger.info("Bienvenido '%s'!", seleccionado)
    return True

def reconf_user():
    '''
    Función de prompt interactivo para reelegir parametros variables en la configuración
    del usuario principal: Metadatos de firma, Perfil de firma, firma visible.

    Se retoma la misma estructura de formulario de creación de usuario agregando con la
    caracteristica especifica de que si se introducen cadenas vacias se REUTILIZARÁN los
    valores preexistentes en la config del principal.
    '''
    import tomli_w
    
    users = load_state_users()
    principal_config_path = users['usuarios'][users.get('principal')]['config_file']
    principal = load_current_user_conf()
    actualizado = principal.copy()
    opciones = []

    logger.info("Reconfiguración de parametros (blanco para mantener valores previos).")
    
    # 4. metadatos de firma
    print()
    logger.info("=== METADATOS DE FIRMA ===")
    ID_FIRMA        = regex.input_regex(patron=regex.ALFANUMERICO, mensaje=f"Identificador de la firma [{principal["metadatos_firma"]["nombre_firma"]}]: ", pista="Alfanumerico mayus/minus.")
    NOMBRE_FIRMANTE = regex.input_regex(patron=regex.SPANISH, mensaje=f"Nombre del firmante [{principal["metadatos_firma"]["nombre_firmante"]}]: ", pista="Solo caracteres del alfabeto en español.")
    RAZON           = regex.input_regex(patron=regex.SPANISH, mensaje=f"Razón de firma [{principal["metadatos_firma"]["razon"]}]: ", pista="Solo caracteres del alfabeto en español.")
    LUGAR           = regex.input_regex(patron=regex.SPANISH, mensaje=f"Lugar de firma [{principal["metadatos_firma"]["lugar"]}]: ", pista="Solo caracteres del alfabeto en español.")
    CONTACTO        = regex.input_regex(patron=regex.CORREOS, mensaje=f"Correo del firmante [{principal["metadatos_firma"]["contacto"]}]: ", pista="Solo correos electrónicos.")
    
    # 5. preferencias sobre el perfil de firma
    print()
    logger.info("=== PERFILES DE FIRMA ===")
    USAR_OCSP    = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"Validación OCSP [{principal["preferencias"]["OCSP"]}] (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_CMS = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"Sello de tiempo TST en su contenedor firma [{principal["preferencias"]["TST_CMS"]}] (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_DSS = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"Sello de tiempo TST en PDF (/DocTimeStamp) [{principal["preferencias"]["TST_DSS"]}] (y/n): ", pista='Solo letras "y", "n".')

    # relación semántica hardcodeada, funciona pero me parece cuestionable.
    for i in [("nombre_firma", ID_FIRMA), ("nombre_firmante", NOMBRE_FIRMANTE), ("razon", RAZON), ("lugar", LUGAR), ("contacto", CONTACTO)]:
        # primero evaluar si existen valores reutilizados
        if not i[1]:
            opciones.append(principal["metadatos_firma"].get(i[0]))
        else:
            opciones.append(i[1])
    actualizado["metadatos_firma"] = {k: opciones[idx] for idx, k in enumerate(principal["metadatos_firma"], 0)}
    opciones.clear()

    for i in [("OCSP", USAR_OCSP), ("TST_CMS", USAR_TSA_CMS), ("TST_DSS", USAR_TSA_DSS)]:
        if not i[1]:
            opciones.append(principal["preferencias"].get(i[0]))
        elif i[1] == 'y':
            opciones.append(True)
        else: # 'n'
            opciones.append(False)

    actualizado["preferencias"] = {k: opciones[idx] for idx, k in enumerate(principal["preferencias"], 0)}
    opciones.clear() # no es necesario pero solo por estetica visual

    toml_actualizado = tomli_w.dumps(actualizado)
    print()
    logger.info("Guardando...")
    try:
        with open(principal_config_path, "w") as f:
            f.write(toml_actualizado)
    except Exception as e:
        logger.error("Error al guardar configuración (%s)", e)
        return False

    else:
        logger.info("Nuevos parametros guardados!")
        return True

#def change_username():
#    users = load_state_users()
#
#    logger.info("=== Usuarios Actuales ===")
#    logger.info("Principal: %s", users['principal'])
#    for idx, i in enumerate(iterable=users['usuarios'].keys(), start=1):
#        logger.info("%s: %s", idx, i)
#
#    print()
#    while True:
#        opcion = int(regex.input_regex(patron=regex.NUMERICO, mensaje="Ingrese el n° de usuario al que desea cambiar nombre: ", pista="Solo números naturales positivos."))
#        if opcion == 0 or opcion > idx: # idx es lo mismo que len() sobre los usuarios
#            logger.warning("No existe un usuario con ese número. Vuelva a ingresarlo.")
#        else:
#            seleccionado = list(users['usuarios'].keys())[opcion - 1] # -1 por el start en enumerate
#            break
#
#    while True:
#        nuevo_nombre = regex.input_regex(patron=regex.ASCII_SIMPLE, mensaje="Nuevo nombre: ", pista="Alfanumerico mayus/minus, guiones medio, bajo, puntos y espacios intermedios.")
#        if not nuevo_nombre in (i for i in users['usuarios']):
#            break
#        logger.warning("El usuario ingresado YA EXISTE. Ingrese uno diferente!")    
#
#    users['usuarios'][seleccionado] = nuevo_nombre
#    if seleccionado == users['principal']:
#        users['principal'] = nuevo_nombre
#    
#    # TODO: TERMINAAAR

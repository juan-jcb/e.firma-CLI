import logging, getpass, tomllib, json, time, sys
from pathlib import Path
from hashlib import sha256
from colorama import Fore

from efcli.core import core_utils, cripto, registros, wrappers, regex, pki, x509
from . import xdg_config, mensajes
from .bootstrap import check_env

logger = logging.getLogger(__name__)

def new_user(mensajes: dict, es_init: bool = False) -> dict:
    """
    Plantilla general de inputs para creación de nuevos usuarios. Se usa
    principalmente en 'efcli init' y 'efcli user --add'.
    
    :param mensajes:
        `dict` de `efcli.xdg.mensajes` con los textos para mostrar en cada paso
        de la creación del usuario para gestionar el contexto, descripciones
        cortas o descripciones largas de cada paso.

    :param es_init:
        `bool` para indicar si es ejecución de init() y entrar a bloque de
        gestión para usuarios actuales.
        `False` asume entorno externo viable previo (usuarios ya existentes)
        y evalua nuevas entradas de forma acorde.
        `True` no asume entorno externo previo: lógica de ejecución tipica
        de init().
    
    :return dict:
        Diccionario de estructura predecible para utilizarse como plantilla
        de usuario nuevo para desglosar su lógica posterior para el guardado
        de dichos datos.
    """
    # 1. Directorio de firmas (se maneja solo en init())

    # 2. Nombre de usuario local
    print(mensajes['usuario_local'])
    if not es_init:
        users = xdg_config.load_state_users()

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

    USER_DIR = xdg_config.CONFIG_DIR / NOMBRE_USUARIO
    USER_CONFIG_FILE = USER_DIR / f"{NOMBRE_USUARIO}.toml"

    # 3. Archivos de e.firma
    sys.stdout.write("\033[2J\033[3J\033[H")
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
                logger.info("Certificado cargado.")
                logger.info("Validando contra PKI de Banxico...")
                if not pki.es_cert_banxico(cert=crt):
                    logger.error("El certificado ingresado NO pertence a la PKI del Banco de México!! Ingrese un certificado nuevamente.")
                    continue
                print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Su certificado pertenece a la PKI de Banxico!")
                print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Entidad: {x509.leer_subject_simple(crt)} ({encode})")
                
                CERT_USUARIO = USER_DIR / f"{NOMBRE_USUARIO}.crt"
                fingerprint_pubcrt = crt.public_key.sha256
                break
        else:
            logger.warning("La ruta es incorrecta, ingresela de nuevo!")
            continue
    
    print()
    while True:
        pkey_input = Path(input("Ruta absoluta de la clave privada del firmante (.key): "))
        if pkey_input.is_file():
            try:
                cifrada, encode = cripto.es_pkey_cifrada(ruta_pkey=pkey_input)
            except Exception:
                logger.warning("El archivo ingresado no es una clave privada. Ingresela nuevamente.")
                continue
            else:
                if cifrada:
                    logger.info("Clave privada (%s) CIFRADA!", encode)
                    logger.info("Para garantizar identidad criptográfica es necesario comparar si la clave que ingresó corresponde a la del certificado!")
                    logger.info("Descifre momentaneamente su clave para calcular valores públicos y compararlos (no se almacenará nunca su contraseña).")
                    while True:
                        password = getpass.getpass(prompt="Ingrese su contraseña: ", echo_char="*").encode('utf-8')
                        if cripto.es_passwd_de_pkey(ruta_pkey=pkey_input, tipo_encode=encode, passwd=password):
                            break
                        else:
                            print("Contraseña INCORRECTA, vuelva a ingresarla.")
                else:
                    logger.info("Clave privada (%s) SIN cifrado.", encode)
                    password = None
                
                logger.info("Comparando fingreprints...")
                fingerprint_pubkey = sha256(data=cripto.bytes_publicos_rsa(ruta_pkey=pkey_input, encode=encode, password=password)).digest()
                if not fingerprint_pubcrt == fingerprint_pubkey:
                    logger.error("El fingerprint de su clave NO coincide con el de la clave en el certificado! ¿Ingresó una diferente?")
                    continue
                
                print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Claves COINCIDEN!")
                print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Fingreprint SHA-256: {fingerprint_pubcrt.hex(sep=":").upper()}")
                PKEY_USUARIO = USER_DIR / f"{NOMBRE_USUARIO}.key"
                break
        else:
            logger.warning("La ruta es incorrecta, ingresela de nuevo!")
    time.sleep(2.5)

    # 4. Metadatos de firma
    sys.stdout.write("\033[2J\033[3J\033[H")
    print(mensajes['metadatos_firma'])
    ID_FIRMA        = regex.input_regex(patron=regex.ALFANUMERICO, mensaje="Identificador de la firma: ", pista="Alfanumerico mayus/minus.")
    NOMBRE_FIRMANTE = regex.input_regex(patron=regex.SPANISH, mensaje="Nombre del firmante: ", pista="Solo caracteres del alfabeto en español.")
    RAZON           = regex.input_regex(patron=regex.SPANISH, mensaje="Razón de firma: ", pista="Solo caracteres del alfabeto en español.")
    LUGAR           = regex.input_regex(patron=regex.SPANISH, mensaje="Lugar de firma: ", pista="Solo caracteres del alfabeto en español.")
    CONTACTO        = regex.input_regex(patron=regex.CORREOS, mensaje="Correo del firmante: ", pista="Solo correos electrónicos.")
    time.sleep(1)

    # 5. Preferencias de perfil de firma.
    sys.stdout.write("\033[2J\033[3J\033[H")
    print(mensajes['pefiles_firma'])
    USAR_OCSP    = regex.input_regex(patron=regex.SI_NO, mensaje="¿Usar validación OCSP? (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_CMS = regex.input_regex(patron=regex.SI_NO, mensaje="¿Usar sello de tiempo en su firma (contrafirma en CMS)? (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_DSS = regex.input_regex(patron=regex.SI_NO, mensaje="¿Usar sello de tiempo en el PDF (TST en /DocTimeStamp)? (y/n): ", pista='Solo letras "y", "n".')
    perfil_firma = [f"{i == 'y'}".lower() for i in [USAR_OCSP, USAR_TSA_CMS, USAR_TSA_DSS]] # me parace cutre, pero eh, deja en minisculas un mapeo de booleanos para usar toml
    time.sleep(1)

    # 6. Preferencias de uso del programa.
    sys.stdout.write("\033[2J\033[3J\033[H")
    print(mensajes['preferencias_uso'])
    AUTOCONFIRMAR_NORMALIZADOS = regex.input_regex(patron=regex.SI_NO, mensaje="¿Usar confirmación automática en los prompts para normalización de PDFs? (y/n): ", pista='Solo letras "y", "n".')
    MANTENER_NORMALIZADOS = regex.input_regex(patron=regex.SI_NO, mensaje="¿Mantener PDFs normalizados (si los hay) al terminar las sesiones de firma? (y/n): ", pista='Solo letras "y", "n".')
    preferencias_uso = [f"{i == 'y'}".lower() for i in [AUTOCONFIRMAR_NORMALIZADOS, MANTENER_NORMALIZADOS]]

    # #!. skeleton de usuario (string -> TOML, TOML -> dict)
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
    
[perfiles_firma]
# validación externa sobre el x509 del firmante con OCSP (Eleva de Perfil B a Pefil L)
OCSP = {perfil_firma[0]}
# TST en el CMS del firmante (Añade Perfil T)
TST_CMS = {perfil_firma[1]}
# TST en /DocTimeStamp del PDF (Añade Perfil A)
TST_DSS = {perfil_firma[2]}

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

[preferencias_uso]
autoconfirmar_normalizaciones = {preferencias_uso[0]}
mantener_normalizados = {preferencias_uso[1]}

# Consideraciones adicionales.
# 
# Según el flujo de operaciones PAdES, la configuración de una TSA para timestamping en DSS NO debería
# estár en el dirccionario de preferencias, sin embargo un firmante individual, dado que es el único
# participante tiene poder de desición completo sobre si quiere utilizar TSTs incrementales o no en el
# /DocTimeStamp de los PDFs que firma, por lo que la configuración de una TSA para este proposito adquiere
# indirectamente el caracter de "metadatos de firma del firmante" y se prefiere en este diccionario
# (aunque técnicamente no pertenezca a los metadatos "reales" de su firma).
    
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

@wrappers.salida_limpia()
@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def add_user() -> None:
    """
    Función de prompt interactivo para añadir a un usuario nuevo. Uso post-init.
    Se asume entorno externo viable.
    """
    nuevo = new_user(mensajes=mensajes.mensajes_adduser, es_init=False)
    if nuevo:
        import shutil
        users = xdg_config.load_state_users()

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
        with open(xdg_config.STATE_USERS_FILE, "w") as f:
            f.write(updated_users)

        logger.info("Usuario '%s' creado correctamente!", NOMBRE_USUARIO)

@wrappers.salida_limpia()
@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def del_user() -> None:
    """
    Función de prompt interactivo para borrar a un usuario del JSON de usuarios.
    Para borrar require haber minimo 2 usuarios.
    No se puede borrar a usuario principal.
    Se asume entorno externo viable.
    """
    users = xdg_config.load_state_users()

    logger.info("=== Usuarios Actuales ===")
    logger.info("Principal: %s", users['principal'])
    for idx, i in enumerate(iterable=users['usuarios'].keys(), start=1):
        logger.info("%s: %s", idx, i)

    if len(users['usuarios']) == 1:
        logger.error("No puede borrar usuarios habiendo solo 1 (ㆆ_ㆆ) Saliendo...")
        exit()

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

    logger.info("Ha seleccionado al usuario '%s'\n", seleccionado) 
    core_utils.continuar_salir_msj(msj='¿Desea borrarlo? (y/n): ', si_continua='Borrando...', si_sale='Saliendo...')

    try:
        import shutil
        shutil.rmtree(users['usuarios'][seleccionado]['user_dir'])
    except FileNotFoundError:
        logger.error("El directorio no existe: '%s'", i)
        exit()
    except PermissionError:
        logger.error("Sin permisos para eliminar: '%s'", i)
        exit()
    except Exception as e:
        logger.error("%s", e)
        exit()
    else:
        del(users['usuarios'][seleccionado])
        updated_users = json.dumps(obj=users, indent=2, ensure_ascii=False)
        with open(xdg_config.STATE_USERS_FILE, "w") as f:
            f.write(updated_users)

        logger.info("Usuario '%s' borrado correctamente!", seleccionado)

@wrappers.salida_limpia()
@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def change_user() -> None:
    """
    Función de prompt interactivo para cambiar de usuario principal según
    los usuarios que hayan disponibles en el JSON de usuarios.
    Se asume entorno externo viable.
    """
    users = xdg_config.load_state_users()

    logger.info("=== Usuarios Actuales ===")
    logger.info("Principal: %s", users['principal'])
    for idx, i in enumerate(iterable=users['usuarios'].keys(), start=1):
        logger.info("%s: %s", idx, i)

    if len(users['usuarios']) == 1:
        logger.error("No puede cambiar de usuario habiendo solo 1 (ㆆ_ㆆ) Saliendo...")
        exit()

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
    with open(xdg_config.STATE_USERS_FILE, "w") as f:
        f.write(updated_users)

    print()
    logger.info("Bienvenido '%s'!", seleccionado)

@wrappers.salida_limpia()
@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def reconf_user() -> None:
    """
    Función de prompt interactivo para reelegir parametros variables en la configuración
    del usuario principal: Metadatos de firma, Perfil de firma, firma visible.

    Se retoma la misma estructura de formulario de creación de usuario agregando con la
    caracteristica especifica de que si se introducen cadenas vacias se REUTILIZARÁN los
    valores preexistentes en la config del principal.

    Se asume entorno externo viable.
    """
    import tomli_w
    
    users = xdg_config.load_state_users()
    principal_config_path = users['usuarios'][users.get('principal')]['config_file']
    principal = xdg_config.load_principal_conf()
    dict_actualizado = principal.copy()
    opciones = []

    logger.info("Reconfiguración de parametros (dejar en blanco para mantener valores previos).")
    
    # 5. preferencias sobre el perfil de firma
    print()
    logger.info("=== PERFILES DE FIRMA ===")
    USAR_OCSP    = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"Validación externa OCSP [{principal["perfiles_firma"]["OCSP"]}] (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_CMS = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"Sello de tiempo en firma [{principal["perfiles_firma"]["TST_CMS"]}] (y/n): ", pista='Solo letras "y", "n".')
    USAR_TSA_DSS = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"Sello de tiempo en PDF [{principal["perfiles_firma"]["TST_DSS"]}] (y/n): ", pista='Solo letras "y", "n".')

    # 6. Preferencias de uso del programa.
    print()
    logger.info("=== PREFERENCIAS DE USO ===")
    AUTOCONFIRMAR_NORMALIZADOS = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"¿Normalización automática de PDFs? [{principal["preferencias_uso"]["autoconfirmar_normalizaciones"]}] (y/n): ", pista='Solo letras "y", "n".')
    MANTENER_NORMALIZADOS = regex.input_regex(patron=regex.SI_NO_BLANK, mensaje=f"¿Mantener PDFs normalizados? [{principal["preferencias_uso"]["mantener_normalizados"]}] (y/n): ", pista='Solo letras "y", "n".')

    # 4. metadatos de firma (queda al final porque es lo que menos varia de los 3 en reconf, y la mayoría de las veces solo se pisotea el ENTER.)
    print()
    logger.info("=== METADATOS DE FIRMA ===")
    ID_FIRMA        = regex.input_regex(patron=regex.ALFANUMERICO, mensaje=f"Identificador de la firma [{principal["metadatos_firma"]["nombre_firma"]}]: ", pista="Alfanumerico mayus/minus.")
    NOMBRE_FIRMANTE = regex.input_regex(patron=regex.SPANISH, mensaje=f"Nombre del firmante [{principal["metadatos_firma"]["nombre_firmante"]}]: ", pista="Solo caracteres del alfabeto en español.")
    RAZON           = regex.input_regex(patron=regex.SPANISH, mensaje=f"Razón de firma [{principal["metadatos_firma"]["razon"]}]: ", pista="Solo caracteres del alfabeto en español.")
    LUGAR           = regex.input_regex(patron=regex.SPANISH, mensaje=f"Lugar de firma [{principal["metadatos_firma"]["lugar"]}]: ", pista="Solo caracteres del alfabeto en español.")
    CONTACTO        = regex.input_regex(patron=regex.CORREOS, mensaje=f"Correo del firmante [{principal["metadatos_firma"]["contacto"]}]: ", pista="Solo correos electrónicos.")

    # relación semántica hardcodeada, funciona pero me parece cuestionable.
    for i in [("nombre_firma", ID_FIRMA), ("nombre_firmante", NOMBRE_FIRMANTE), ("razon", RAZON), ("lugar", LUGAR), ("contacto", CONTACTO)]:
        # primero evaluar si existen valores reutilizados
        if not i[1]:
            opciones.append(principal["metadatos_firma"].get(i[0]))
        else:
            opciones.append(i[1])
    dict_actualizado["metadatos_firma"] = {k: opciones[idx] for idx, k in enumerate(principal["metadatos_firma"], 0)}
    opciones.clear()

    for i in [("OCSP", USAR_OCSP), ("TST_CMS", USAR_TSA_CMS), ("TST_DSS", USAR_TSA_DSS)]:
        if not i[1]:
            opciones.append(principal["perfiles_firma"].get(i[0]))
        elif i[1] == 'y':
            opciones.append(True)
        else: # 'n'
            opciones.append(False)
    dict_actualizado["perfiles_firma"] = {k: opciones[idx] for idx, k in enumerate(principal["perfiles_firma"], 0)}
    opciones.clear()

    for i in [("autoconfirmar_normalizaciones", AUTOCONFIRMAR_NORMALIZADOS), ("mantener_normalizados", MANTENER_NORMALIZADOS)]:
        if not i[1]:
            opciones.append(principal["preferencias_uso"].get(i[0]))
        elif i[1] == 'y':
            opciones.append(True)
        else: # 'n'
            opciones.append(False)
    dict_actualizado["preferencias_uso"] = {k: opciones[idx] for idx, k in enumerate(principal["preferencias_uso"], 0)}
    opciones.clear() # no es necesario pero solo por estetica visual

    toml_actualizado = tomli_w.dumps(dict_actualizado)
    print()
    logger.info("Guardando...")
    try:
        with open(principal_config_path, "w") as f:
            f.write(toml_actualizado)
    except Exception as e:
        logger.error("Error al guardar configuración (%s)", e)
        exit()

    else:
        logger.info("Nuevos parametros guardados!")

#def change_username():
#    users = xdg_config.load_state_users()
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

@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def print_current_user() -> None:
    """
    Imprime un resumen compacto sobre el usuario principal.
    Se asume entorno externo viable.
    """
    users = xdg_config.load_state_users()
    principal_name = users.get('principal')
    principal_dict = users['usuarios'].get(users['principal'])
    cert_path = principal_dict['cert']
    with open(cert_path, "rb") as f:
        cert, _ = x509.cargar_cert_asn1(cert=f.read())

    with registros.modded_logs(target_logger=logger, level=logging.DEBUG):
        logger.debug("Usuario: %s", principal_name)
        logger.debug("e.firma: %s", x509.leer_subject_simple(cert))

@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def print_current_user_conf() -> None:
    """
    Imprime la configuración del usuario principal de forma compacta y legible (estiliza su TOML).
    Se asume entorno externo viable.
    """
    users = xdg_config.load_state_users()
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
        logger.debug("Validación OCSP (L): %s", cnf['perfiles_firma']['OCSP'])
        logger.debug("Sello de tiempo en firma (T): %s", cnf['perfiles_firma']['TST_CMS'])
        logger.debug("Sello de tiempo en PDF (A): %s", cnf['perfiles_firma']['TST_DSS'])

@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def print_current_user_toml() -> None:
    """
    Imprime la configuración del usuario principal tal cual desde su TOML.
    Se asume entorno externo viable.
    """
    users = xdg_config.load_state_users()
    with open(users['usuarios'].get(users['principal'])['config_file'], "r") as f:
        print(f.read())

@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def list_users() -> None:
    """
    Imprime los usuarios disponibles en el programa desde el JSON de usuarios.
    Se asume entorno externo viable.
    """
    users = xdg_config.load_state_users()

    logger.info("=== USUARIOS ===")
    logger.info("Principal: %s", users['principal'])
    for idx, i in enumerate(iterable=users['usuarios'].keys(), start=1):
        logger.info("%s: %s", idx, i)
        for v, k in users['usuarios'][i].items(): # porque son diccionarios
            if not Path(k).exists():
                logger.info("[%s] '%s' no fue encontrado. Saliendo...", i , k)
                exit()
            logger.info("   %s: '%s'", v, k)

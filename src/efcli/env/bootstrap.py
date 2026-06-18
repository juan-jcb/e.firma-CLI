import logging, shutil, json, time
from pathlib import Path

from efcli.env.config import APP, CONFIG_DIR, DATA_DIR, STATE_DIR, PKI_DIR, PKI_DEFAULTS, STATE_FILE, STATE_USERS_FILE, GLOBAL_CONFIG_FILE
from efcli.pki.x509_utils import cargar_cert_asn1, leer_subject_simple
from efcli.utils import cripto, registros, wrappers, regex

logger = logging.getLogger(__name__)

LIVE_ENV_FILES = (CONFIG_DIR, DATA_DIR, STATE_DIR) # GLOBAL_CONFIG_FILE['pdf_ruta_base']

@wrappers.salida_limpia()
def init():
    print("""Bienvenido a e.firma CLI!

Una herramienta de terminal que permite operar de manera simplificada en el contexto de la PKI del
Banco de México y el SAT.

Principalmente enfocada a las operaciones de firma digital que se pueden realizar con las claves
privadas RSA que son proporcionadas por diferentes entidades como el SAT en su respectivo trámite
para emisión de e.firma.

'e.firma CLI' le otorga al poseedor de una e.firma la capacidad de operar su e.firma, realmente como
una firma electrónica para firmar sus propios documentos de manera gratuita bajo el esquema PAdES:
\"PDF Advanced Electronic Signatures\" en todos sus perfiles de firma:

    - 'Basic (B)'
    - 'Long-Term (L)'
    - 'Timestamp (T)'
    - 'Archival (A)'

SOBRE EL PROPÓSITO.

Si bien las firmas digitales 'per se' tienen un uso más extendido en la comunicación segura entre
sistemas (sin intervención humana), el hecho de que Banxico haya decido operar este esquema de
entidades criptográficas bajo el estándar ASN.1/X.509, permite ampliar las capacidades de dichas
firmas hacia ámbitos con una repercución, por así decirlo \"más tangible\" y notoria para los dueños
de estos artefactos; como lo es la firma estandarizada de documentos PDF bajo el esquema PAdES (en
la cual se centra la presente herramienta) y que es perfectamente compatible con cualquier PKI,
sea pública o privada, como en el caso de la PKI privada de Banxico y sus autoridades de certificación
intermedias como el SAT.

Bajo este contexto es que se desarrolla 'e.firma CLI'; con el fin de aprovechar la criptografía
subyacente de estos artefactos (ya existentes para cualquiera que haya realizado su trámite de emisión
de e.firma) para realizar firmas digitales, y por ende las caracteristicas de integridad, autenticidad
y no redudio que la criptografía asimétrica le otorga a las firmas efectuadas (a mi jucio muy superior
a las firmas autógrafas, siempre y cuando se comprenda cómo operan con estos elementos), así como el
ecosistema de validación de entidades denotado por los certificados X.509 que acompañan a las claves
y pertenecen al contexto jerarquico de la PKI del Banco de México.

De tal modo que realmente se haga valer la terminología de \"firma electrónica\" que la e.firma
publicita, y que éstos artefactos criptográficos tengan un uso real y asequible para sus poseedores,
más allá de ser un factor de autenticación generico utilizado por SAT e IMSS en sus páginas web para
permitir el acceso a perfiles de usuario ¯\\_(ツ)_/¯, y si acaso realizar firmas puntuales, pero siempre
bajo contexto cerrado (principalmente facturas), en pocas palabras, sin control real del usuario sobre
el material que ya posee y los alcances potenciales que este puede tener más allá de la criptográfia;
gracias a la homologación de "firma equivalente a la autógrafa", fundamentada en los articulos 1803
fracción I del Código Civil Federal, y de los articulos: 89 párrafo 3 y 97 párrafo 2 fracciones I, II,
III y IV del Código de Comercio.

En terminos prácticos se puede entender a la e.firma como un mecanismo de identidad fundamentado en
criptografía, y que adquiere el caracter de "identidad pública en contexto nacional" en el momento
que una de estas claves criptográficas es vinculada a un certificado X.509 emitido por una entidad
de confianza; siendo esta la entidad raíz en una PKI (el Banco de México), y de la que se extienden
las entidades certificadoras intermedias (como el SAT) de la cual emiten los certificados finales del
poseedor (los contribuyentes).

Es por tanto que la existencia de una determinada e.firma 'avala la existencia' de un determinado
contribuyente dado el proceso de autenticación (el trámite) que se realiza personalmente frente a la
entidad certificadora de confianza (el SAT), de tal modo que cualquier firma digital efecutada por una
clave privada que esté asociada a un certificado x509 perteneciente a la PKI del banco de méxico, se
asume como: 'de X contribuyente', y por ende como: 'de X Ciudadano Méxicano con papeles en regla' ya
que la entidad de confianza los corroboró *previo* a crear las claves y emitir los certificados (ademas
claro ¯\\_(ツ)_/¯, de aprovechar el interludio del proceso para recolectar datos biometricos, que nada
tienen que ver con la naturaleza de éstos artefactos criptográficos y su operación real)

MATIZ OPERATIVO.

e.firma CLI permite obtener el perfil de firma más alto para un pdf firmado según PAdES (PAdES-LTA)
el cual en sus perfiles 'T' y 'A' hacen uso de sellos de tiempo 'TST' (RFC 3161).

No obstante es necesario señalar que la secretaría de economia decidió terciarizar las funciones de la
PKI de Banxico mediante lo que ellos denominan como Prestador de Servicios de Certificación (PSC);
empresas de terceros que forman parte operativa en la PKI de Banxico, avalandolos tanto como CA intermedia
para emisión de certificados finales, como TSA dedicadas a la emisión tokens de sellado de tiempo (TST).

Esto tiene implicaciónes juridicas y monetarias más que puramente técnicas y criptográficas.

Las TSAs de PSC son el caso que en mayor o menor medida pueden afectar a los perfiles de firma relacionados
con los sellos de tiempo (Timestamp y Archival), ya que según la NOM-151 un sello de tiempo (denominado
por la NOM como "constancia de certificación" aunque su nombre real es TimeStamp Token o simplemente TST)
que sea emitido por una TSA de un Prestador de Servicios de Certificación es lo que otorga la cualidad
juridica de 'fecha cierta' a una determinada firma digital.

Esta consideración como tal NO afecta a la criptografia subyacente de las claves, los certificados, las
firmas realizadas, y ni siquiera los propios TST; puesto que el TST que puede emiter una TSA pública es
criptográficamente igual de válido al TST emitido por la TSA de un Prestador de Servicios de Certificación.

La unica diferencia real que existe entre las TSAs públicas y las TSAs de PSC es que los PSC son avalados
por la secretaria de economia para ejercer como TSA en este contexto PKI. Además de que un PSC agrega 2
extensiones opcionales extra a sus sellos de tiempo (extensiones opcionales que no alteran la función
principal del TST para fungir como sello de tiempo).

Citando los apendices A.7.1 y A.7.4 de la NOM-151:

    Una de las extensiones a usar en la presente NOM se encuentra especificada en el RFC 5280.
    Las extensiones no se marcarán como críticas.

    Con la finalidad de identificar el inicio de vigencia de la constancia, se incorporan los dos
    siguientes elementos, cuya definición se expresa en la notación ASN.1

        id-nom-ini-time OBJECT IDENTIFIER ::= {2 16 484 101 10 316 20 37 1117}
        NOM151IniTime ::= GeneralizedTime

En términos prácticos el TST de un PSC y el TST de una TSA pública son criptográficamente iguales según
su función principal de sello de tiempo, y solo se diferencian en 2 cosas:

    - El PSC fue avalado por una entidad de gobierno 
    - La TSA del PSC generó un TST con 2 extensiones opcionales en la estructura del sello.

La firma de la TSA sobre el hash enviado en un TSQ (RFC 3161) se aplica de la misma manera para generar
un TST idenpendientemente de si la TSA es pública de internet o si es de un PSC avalado por Economia.
Además claro, de que el acceso a la TSA del PSC para obtener su sellos de tiempo; está debidamente
protegida detras de un muro de pago ¯\\_(ツ)_/¯. Una operación que es técnicamente gratuita en el contexto
actual de internet se restringe por cuestiones administrativas y se aprovecha para cobrar en el proceso.

A mi juicio lo más adecuado sería que Banxico gestione su propia TSA así como gestiona su propia CA raíz,
y que exista 1 sola TSA pública que cualquiera pueda utilizar y sea válida a nivel nacional "( – ⌓ – ).

Como conclusión a esto podemos resumir.

    - e.firma CLI puede firmar con sellos de tiempo T y A de ambos tipos de TSA, sea pública o de PSC

    - Un firma en perfil T y/o A de e.firma CLI es criptográficamente igual de válida tanto si proviene
      de TSA pública como de TSA de PSC.

    - Una firma sin TST de PSC unicamente no posee fecha cierta (que aplica a nivel méxico) y de ello
      se derivan sus respectivas implicaciones juridicas para el documento firmado.

    - Si se utilizan TSTs de PSC evidentemente se tendrá que pagar para obtener acceso a su endpoint
      y posteriormente usarlo en esta herramienta.
""")

    print("""INTRODUCCIÓN AL USO.

Para facilitar la interacción con ésta herrienta en su uso cotidiano se emplean configuraciones de
usuario las cuales necesita completar con algunos datos relevantes.

Se le pide que lea atentamente las indicaciones que a continuación se le presentan para que tenga
una introducción adecuada sobre el uso de esta herramienta.

Sientase libre de cancelar en cualquier momento este procedimiento utilizando CTRL+C y reiniciar con
el mismo comando 'efcli init
""")

    print("""CONFIGURACIÓN INICIAL.

1. Usuario local.

e.firma CLI utiliza perfiles de usuario locales que recopilan los datos más
relevantes para efectuar una firma digital.

A continuación se desglosarán los campos necesarios para crear un perfil de
usuario completo y establecer la configuración global del programa.

Para comenzar a utilizar efcli se requiere unicamente de 1 usuario, el cual
si posteriormente lo desea podrá editar, crear nuevos usuarios, borrar ya
existentes o consultar configuraciones mediante el submodulo 'efcli user'.
""")

    NOMBRE_USUARIO = regex.input_regex(regex=regex.ASCII_SIMPLE, mensaje="Nombre de usuario local: ", pista="Alfanumerico mayus/minus, guiones medio, bajo y puntos.")

    time.sleep(1)
    print("\033[H\033[2J", end="")
    print("""2. Directorio de firmas.

e.firma CLI definirá en su $HOME un directorio dedicado a las operaciones
involucradas con firmas digitales. Este directorio está diseñado para que
ahí mueva los archivos .pdf que desea firmar (puede ser 1 pdf o más, ya que
la lógica para firmar es la misma sin importar si la firma es por archivo
individual o por lote).

Será en ese directorio cuyo nombre usted indice que se generarán los resultados
de cada firma en un forma de un subdirectorio nuevo fácil de indentificar
creado en cada instancia o sesión de firma.
""")

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

    USER_DIR = CONFIG_DIR / NOMBRE_USUARIO
    USER_CONFIG_FILE = USER_DIR / f"{NOMBRE_USUARIO}.toml"

    time.sleep(1)
    print("\033[H\033[2J", end="")
    print(f"""3. Firma electrónica.

Para firmar documentos se requiere de los archivos incluidos en su e.firma:

    - Clave privada (archivo .key)
    - Certificado X.509 (archivo .cer)

Este programa *realizará 1 copia* de cada archivo y las almacenará localmente
en la ruta XDG estándar 'XDG_DATA_HOME' del usuario actual en su sistema:

    '/home/mi_usuario/.config/{APP}/{NOMBRE_USUARIO}/{NOMBRE_USUARIO}.key'
    '/home/mi_usuario/.config/{APP}/{NOMBRE_USUARIO}/{NOMBRE_USUARIO}.crt'

Y lo mismo para cada usuario nuevo creado.
""")

    while True:
        cert_input = Path(input("Ruta absoluta del certificado del firmante (.cer): "))
        if cert_input.is_file():
            try:
                crt, encode = cargar_cert_asn1(cert=cert_input)
            except Exception:
                logger.warning("El archivo ingresado no es un certificado. Ingreselo nuevamente.")
                continue
            else:
                print(f"Correcto. {leer_subject_simple(crt)} ({encode})")
                CERT_USUARIO = USER_DIR / f"{NOMBRE_USUARIO}.crt"
                break
        else:
            logger.warning("La ruta es incorrecta, ingresela de nuevo!")
            continue

    while True:
        pkey_input = Path(input("Ruta absoluta de la clave privada del firmante (.key): "))
        if pkey_input.is_file():
            try:
                cifrada, encode = cripto.es_pkey_cifrada(pkey=pkey_input)
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

    time.sleep(2)
    print("\033[H\033[2J", end="")
    print(f"""4. Metadatos de su firma.

Cada vez que usted efectua una firma, independientemente del perfil de
firma usado (B, L, T, A) su firma incluirá metadatos visibles en cualquier
validador de firmas digitales (como Adobe Acrobat Reader) para facilitar
la distinción visual, por ejemplo en casos donde 1 mismo PDF posee multiples
firmas.

Estos metadatos incluyen:

    - Identificador de la firma: Cualquier cadena de texto dificil de
      repetir (recomiendo usar el CURP ya que es un valor relativamente
      unico).

    - Nombre del firmante: El nombre de la persona que realiza la firma.
      (en el 99% de los casos es el dueño de la e.firma)

    - Razón de firma: Justificación corta de cómo o por qué se firma
      (ej: "Firmado personal con mi e.firma")

    - Lugar de firma: Ubicación generalizada de la firma (ej: "México",
      "Puebla", "Administración", "Sistemas")

    - Contacto del firmante: Comunmente el correo del firmante.

Matiz adicional.

Si usted duda sobre utilizar datos personales en los campos de metadatos
de su firma, esto no supone una exposición innecesaria de información
puesto que el propio certificado X.509 de su e.firma ya incluye datos
relevantes su dueño, especificamente en el 'Subject:' y en los campos:

    - CN=, name=, O=            (contiene su nombre completo)
    - serialNumber=             (contiene su CURP)
    - x500UniqueIdentifier=     (contiene su RFC)
    - emailAddress=             (contiene el correo que uso en el trámite)

Cualquier firma PAdES incluye el certificado x509 del firmante (además de
los metadatos), por lo que aunque no los incluya, si se firma mediante PAdES,
cualquiera que valide la firma podrá leer los campos de su certificado para
saber de quién proviene.

Puede llenar los campos o dejarlos en blanco a criterio.
""")

    ID_FIRMA = regex.input_regex(regex=regex.ALFANUMERICO, mensaje="Identificador de la firma: ", pista="Alfanumerico mayus/minus.")
    NOMBRE_FIRMANTE = regex.input_regex(regex=regex.SPANISH, mensaje="Nombre del firmante: ", pista="Solo caracteres del alfabeto en español.")
    RAZON = regex.input_regex(regex=regex.SPANISH, mensaje="Razón de firma: ", pista="Solo caracteres del alfabeto en español.")
    LUGAR = regex.input_regex(regex=regex.SPANISH, mensaje="Lugar de firma: ", pista="Solo caracteres del alfabeto en español.")
    CONTACTO = regex.input_regex(regex=regex.CORREOS, mensaje="Correo del firmante: ", pista="Solo correos electrónicos.")

    # Con la declaración explcita de los certificados de una PKI se deja de ser dependiente solo al conetxto
    # de la PKI de banxico y se puede operar con cualquier otra siempre que se tengan sus x509 organizados.
    skel_global = f'''# Configuración global de e.firma CLI.

pdf_ruta_base = "{PDF_RUTA_BASE}"

[PKI]
trust_roots = "{PKI_DIR / 'banxico_root_bundle.pem'}"
intermediate_cas = "{PKI_DIR / 'sat_intermedia_bundle.pem'}"

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

    skel_user = f'''# Configuración de usuario {NOMBRE_USUARIO}

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
OCSP = false

# TST en el CMS del firmante (Añade Perfil T)
TST_CMS = false

# TST en /DocTimeStamp del PDF (Añade Perfil A)
TST_DSS = false

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

    # TODO: no me agrada esta estructura.
    def hacer_dirs() -> None:
        for i in (CONFIG_DIR, DATA_DIR, STATE_DIR, PKI_DIR, USER_DIR, PDF_RUTA_BASE):
            i.mkdir(parents=True, exist_ok=True)

    def seed_config() -> None:
        with open(GLOBAL_CONFIG_FILE, "w") as f: 
            f.write(skel_global)

        with open(USER_CONFIG_FILE, "w") as f: 
            f.write(skel_user)
        
        shutil.copy2(src=cert_input, dst=CERT_USUARIO)
        shutil.copy2(src=pkey_input, dst=PKEY_USUARIO)
        
        for i in PKI_DEFAULTS:
            shutil.copy2(src=i, dst=f"{PKI_DIR}/{i.name}")

    hacer_dirs()
    seed_config()

    init_state_programa = {
            'xdg_dirs': {
                'config_dir': CONFIG_DIR.as_posix(),
                'data_dir': DATA_DIR.as_posix(),
                'state_dir': STATE_DIR.as_posix(),
            },

            'custom_dirs': {
                'pdf_ruta_base': PDF_RUTA_BASE.as_posix(),
                'pki_dir': PKI_DIR.as_posix(),
            },

            'assets': [f"{PKI_DIR}/{i.name}" for i in PKI_DEFAULTS]
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

    state_programa = json.dumps(obj=init_state_programa, indent=2, ensure_ascii=False)
    state_usuarios = json.dumps(obj=init_state_usuarios, indent=2, ensure_ascii=False)

    with open(STATE_FILE, "w") as f:
        f.write(state_programa)
    with open(STATE_USERS_FILE, "w") as f:
        f.write(state_usuarios)

def check_env(log_level=logging.INFO):
    '''
    Evaluación en 2 partes.

    1. Qué los directorios de entorno existan
    2. Qué la configuración de estádo sea coherente.
    '''
    with registros.log_format(fmt="[%(levelname)s] %(message)s", level=log_level, target_logger=logger):

        logger.debug('=== ESTRUCTURA XDG ===')
        for i in LIVE_ENV_FILES:
            if Path(i).exists():
                logger.debug("Existe: '%s'", i)
            else:
                logger.debug("El directorio '%s' no existe.", i)
                return False

        logger.debug('=== ARCHIVOS DE ESTADO ===')
        if Path(STATE_FILE).exists() and Path(STATE_USERS_FILE).exists():
            logger.debug("Existe: '%s'", STATE_FILE)
            logger.debug("Existe: '%s'", STATE_USERS_FILE)


            logger.debug("=== COHERENCIA DEL ENTORNO ===")
            with open(STATE_FILE, "r") as f:
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
            with open(STATE_USERS_FILE, "r") as f:
                usuarios = json.loads(s=f.read())

            logger.debug("Principal: %s", usuarios['principal'])
            for idx, i in enumerate(iterable=usuarios['usuarios'].keys(), start=1):
                logger.debug("%s: %s", idx, i)
                for v, k in usuarios['usuarios'][i].items(): # porque son diccionarios
                    if not Path(k).exists():
                        logger.debug("[%s] '%s' no fue encontrado.", i , k)
                        return False
                    else:
                        logger.debug("%s: '%s'", v, k)

        else:
            logger.debug("Faltan archivos de estado.")
            return False

        return True

def reset_env():
    # TODO: estaría bueno una función read_env() que lea el entorno y retorne dinámicamente un diccionario
    # sobre el cual iterar. De momento se hace hardcodeado:

    import tomllib
    with open(GLOBAL_CONFIG_FILE, "rb") as f:
        global_config = tomllib.load(f)

    for i in (CONFIG_DIR, DATA_DIR, STATE_DIR, global_config['pdf_ruta_base']):
        try:
            shutil.rmtree(i)
            print(f"Directorio borrado: '{i}'")
        except FileNotFoundError:
            print(f"El directorio no existe: '{i}'")
        except PermissionError:
            print(f"Sin permisos para eliminar: '{i}'")
        except Exception as e:
            print(f"Error: {e}")

    print('Entorno externo borrado completamente.')
    return True

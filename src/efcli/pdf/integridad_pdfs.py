import logging
from io import BytesIO
from pathlib import Path
from datetime import datetime, timedelta
from colorama import Fore

from asn1crypto import x509 as asn1_x509
from asn1crypto import keys as asn1_keys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

logging.getLogger("pikepdf").setLevel(logging.WARNING) # pikepdf gestiona su propio logger, mejor silenciar su INFO y usar solo warning
logging.getLogger("pyhanko.pdf_utils.xref").setLevel(logging.ERROR) # [WARNING] Superfluous whitespace found in object header 3 0
from pikepdf import open as pike_open

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields

from pyhanko.sign.general import SigningError
from pyhanko.pdf_utils.misc import PdfReadError, PdfStrictReadError
from pyhanko.pdf_utils.metadata.xmp_xml import XmpXmlProcessingError
from pyhanko.pdf_utils.crypt.api import PdfKeyNotAvailableError

from efcli.core.wrappers import salida_limpia

logger = logging.getLogger(__name__)

def firmante_dummy() -> signers.PdfSigner:
    dummy_pkey_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    dummy_pkey_bytes = dummy_pkey_obj.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Dummy State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Dummy Locality"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dummy Subject"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Dummy Subject"),
    ])

    dummy_cert_obj = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(dummy_pkey_obj.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(datetime.now() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(dummy_pkey_obj, hashes.SHA256())
    )

    dummy_cert_bytes = dummy_cert_obj.public_bytes(serialization.Encoding.DER)

    dummy_simple_signer = signers.SimpleSigner(
        signing_key=asn1_keys.PrivateKeyInfo.wrap(private_key=dummy_pkey_bytes, algorithm='rsa'),
        signing_cert=asn1_x509.Certificate.load(encoded_data=dummy_cert_bytes),
        cert_registry=None
    )

    dummy_sig_meta = signers.PdfSignatureMetadata(
        field_name='firma dummy',
        name='firma dummy',
        reason='firma dummy',
        location='firma dummy',
        contact_info='firma dummy',
        md_algorithm='sha256',
        timestamp_field_name=datetime.now(),
        subfilter=fields.SigSeedSubFilter.PADES,
    )

    dummy_signer = signers.PdfSigner(
        signer=dummy_simple_signer,
        signature_meta=dummy_sig_meta,
        timestamper=None,
        new_field_spec=None,
    )

    return dummy_signer

def normalizar_pdf(pdf: Path, autoconfirmar: bool) -> Path | None:
    """
    Normaliza un PDF malformado o con errores de lectura (prompt interactivo).
    Crea un nuevo archivo PDF en base al original en su misma ruta con un sufijo
    diferenciador.
    
    :param pdf:
        `Path` del PDF a normalizar.

    :return:
        `Path` del PDF nuevo normalizado con el sufijo extendido "_NORMALIZADO"
        en la misma ruta de `pdf`. 
    """
    if not autoconfirmar:
        logger.warning("Puede corregir creando un PDF *nuevo* con el contenido visual del original y firmar ese en su lugar.\n")
        while True:
            opcion = input(f"Reparar '{pdf.name}'? (y/n): ")
            if opcion == 'y' :
                print('Reparando...')
                break
            elif opcion == 'n':
                print(f"No es posible firmar en este estado. Saliendo...")
                exit()
            else:
                print('Ingrese una opción correcta.')

    # lo crea en el mismo directorio donde existe el anterior y retorna el str de ruta os del nuevo
    normalizado_path = Path(f"{pdf.parent}/{pdf.stem}_NORMALIZADO{pdf.suffix}")
    try:
        normalizado = pike_open(filename_or_stream=pdf)
        normalizado.save(filename_or_stream=normalizado_path)
    except Exception:
        logger.critical("No pudo normalizarse PDF: %s. Saliendo...", normalizado_path.name)
        exit()
    else:
        logger.info("REPARADO: %s\n", normalizado_path.name)
        return normalizado_path

def firma_puntual(pdf_stream: BytesIO, firmante: signers.PdfSigner) -> bool:
    try:
        firmante.sign_pdf(
            pdf_out=IncrementalPdfFileWriter(pdf_stream),
            output=BytesIO(),
            existing_fields_only=False,
        )
    except Exception as e:
        print("error en firma puntual (post intento) %s", e)
        return False
    else:
        return True

@salida_limpia()
def pre_firma(lista_pdfs: list, autoconfirmar: bool) -> list | bool:
    """
    Función de comprobación sobre la viabilidad de firma en el/los PDFs originales.

    Se realiza una firma básica 'PAdES-B-B' en memoria con una clave privada RSA
    de 2048 bits y un x509 autofirmado; instanciando a un firmante simple con datos
    genéricos. Esta función tiene como finalidad comprobar la integridad de el/los
    PDFs originales y determinar si son aptos para procesarse con pyhanko previo a
    las firmas reales que sí se almacenan.
    
    En caso de presentar PDFs con inconsistencias se provee una opción de normalización
    y guardado para el/los PDFs en cuestión y posteriormente firmar solo el contenido
    normalizado en el orden originalmente propuesto.

    Esta función se vuelve notoriamente útil en firma de PDFs por lote; donde se
    necesita certeza de integridad sobre los archivos antes de firmarlos en bucle
    y tener una sesión de firma exitosa independientemente de la cantidad de material
    a firmar.
    
    :param lista_pdfs:
        `list` de objetos `Path` con las rutas de todos los .pdf disponibles en la
        ruta base de firmas
    
    :return:
        `list` de `tuple` con 2 elementos:
        
        indice 0: objeto `Path` (normalizado o no) del .pdf a firmar.
        indice 1: `int` incativo de "la siguiente firma" que será incrustada en el PDF
        si es que se firma a posteriori.
    """
    logger.info("Evaluando la integridad de los PDFs...")
    DUMMY_SIGNER = firmante_dummy()
    para_iterar = lista_pdfs.copy()
    normalizados = []
    
    # Desde pre-firma se determina "el siguiente indice disponible" que usará la firma efectiva
    # del firmante real en su sesión de firma.

    # Se basa literalmente en el hecho de que 'pdf.embedded_signatures' es una lista, y las
    # firmas son incrementales en numero natural positivo :p, por lo que la longitud retornada
    # por len() sobre las firmas actuales en éste PDF representa el indice que ocupará la firma
    # real del firmante una vez este la haga, y se usará ese número tal cual. Se entiende que:

    # Si len() retorna 0, no hay firmas el firmante ocupará indice 0
    # Si len() retorna 1, hay 1 firma,  el firmante ocupará indice 1 (la firma existente ya ocupa el 0)
    # Si len() retorna 2, hay 2 firmas, el firmante ocupará indice 2 (las firmas existentes ya ocupan 0 y 1)
    # y así sucesivamente.
    for i in para_iterar:
        lector = None
        escritor = None
        normalizado_path = None
        normalizado_stream = None
        esta_cifrado = False
        idx_pdf_actual = lista_pdfs.index(i)
        siguiente_firma = 0

        with open(f'{i}', 'rb') as f_stream:
            header = f_stream.read()[:5] # Evaluar en primer lugar que el archivo sea un PDF real.

            try:
                lector = PdfFileReader(f_stream)

            except (PdfReadError, PdfStrictReadError) as e:
                if header != b'\x25\x50\x44\x46\x2D': # Header PDF (%PDF-) independiente de la versión.
                    logger.error("NO es un PDF!! '%s' (%s)", i, e)
                    logger.error("Se eliminará éste archivo del material propuesto y se continuará sin él.")
                    lista_pdfs.pop(idx_pdf_actual)
                    continue

                logger.warning("Lectura inicial INCONSISTENTE: %s (%s)", i.name, e)
                normalizado_path = normalizar_pdf(pdf=i, autoconfirmar=autoconfirmar)
                normalizado_stream = open(f'{normalizado_path}', 'rb')
                lector = PdfFileReader(normalizado_stream)
                escritor = IncrementalPdfFileWriter(normalizado_stream)
                i = normalizado_path

            if lector.encrypted:
                esta_cifrado = True
                # Salvaje pero de momento temporal, asumimos que entró en este bloque sin errores de carga inicial y está cifrado
                logger.warning("PDF CIFRADO! /Encrypt en trailer: '%s' (intentando descifrar con cadena vacia...)", i.name)
                lector.decrypt(password="") # vaya nombres raros para hacer lo mismo
                siguiente_firma = len(lector.embedded_signatures)
                if not escritor:
                    escritor = IncrementalPdfFileWriter(f_stream)
                    escritor.encrypt(user_pwd="") # vaya nombres raros para hacer lo mismo

            # Dado que mi flujo contempla la lectura de firmas (y por ende parseo /Root -> /AcroForm -> /Fields)
            # en prefirma; se deberán manejar los casos donde el PDF viene malformado desde un inicio y provoquen
            # PdfStrictReadError POST-instanciación inicial como PdfFileReader() debido al parseo lazy de pyhanko.
            # El primer except de PdfStrictReadError gestiona los casos más evidentes de error inicial para su
            # normalización, éste try: gestiona los casos más particulares pero factibles de malformación del PDF.
            try:
                siguiente_firma = len(lector.embedded_signatures)

            except PdfStrictReadError as e:
                print()
                logger.warning("PDF MALFORMADO: %s (%s)", i.name, e)
                normalizado_path = normalizar_pdf(pdf=i, autoconfirmar=autoconfirmar)
                normalizado_stream = open(f'{normalizado_path}', 'rb')
                lector = PdfFileReader(normalizado_stream)
                escritor = IncrementalPdfFileWriter(normalizado_stream)
                siguiente_firma = len(lector.embedded_signatures)
                i = normalizado_path

            else:
                if not escritor:
                    escritor = IncrementalPdfFileWriter(f_stream)

            try:
                DUMMY_SIGNER.sign_pdf(
                    pdf_out=escritor,
                    output=BytesIO(),
                    existing_fields_only=False,
                )
            except (SigningError, UnicodeDecodeError, XmpXmlProcessingError, PdfStrictReadError) as e:
                print()
                logger.warning("Firma INCONSISTENTE: %s (%s)", i.name, e)
                normalizado_path = normalizar_pdf(pdf=i, autoconfirmar=autoconfirmar)
                normalizado_stream = open(f'{normalizado_path}', 'rb')
                if not firma_puntual(pdf_stream=normalizado_stream, firmante=DUMMY_SIGNER):
                    exit()
                lector = PdfFileReader(normalizado_stream)
                escritor = IncrementalPdfFileWriter(normalizado_stream)
                i = normalizado_path

            finally:
                if normalizado_path and normalizado_stream:
                    normalizado_stream.close()
                    normalizados.append(normalizado_path)

                    # Esta evaluación es contradictoria, pero es para los casos limite donde la normalización de
                    # un PDF cifrado se lo termina quitando. (estaba cifrado, se normalizó, dejo de ser cifrado)
                    if esta_cifrado == True and not lector.encrypted:
                        logger.debug("La normalización del PDF le sacó el cifrado (%s)", normalizado_path)
                        esta_cifrado = False

                print(f'[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Válido: {i.name}')
                lista_pdfs[idx_pdf_actual] = (i, siguiente_firma, esta_cifrado)
                # Cuando se normalice un PDF con errores se incrustará el archivo nuevo normalizado (objeto Path)
                # en el índice del archivo que tuvo problemas al pre-firmar; sustituyendolo en su mismo indice
                # y así retornar una lista consistente con el órden inicial en el que se instanciaron los objetos
                # Path, objetos Path que apuntarán a archivos reales y válidos para firmar.
                # La sustitución con indices a mi juicio parece salvaje, pero en principio se sustenta en el
                # comportamiento normal de cualquier directorio; donde no se puede tener (en el mismo directorio)
                # más de 1 archivo con el mismo nombre. Se entiende que si todos los PDFs existentes en ruta
                # base tienen nombre diferente entonces todos los resultados de .index(i) en 'indice' serán
                # diferentes y por ende no se sutituirá equivocadamente un PDF distinto al pretendido por haber
                # sido "el primero encontrado".

    if len(lista_pdfs) >= 1:
        print(f'[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Material para firmar ({len(lista_pdfs)}) listo.')
        print()
        return (lista_pdfs, normalizados)
    else:
        logger.warning("No hay suficiente material para firmar. Saliendo...")
        exit()


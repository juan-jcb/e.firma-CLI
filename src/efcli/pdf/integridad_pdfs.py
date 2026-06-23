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

from pikepdf import open as pike_open
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields

from efcli.utils.wrappers import salida_limpia

logger = logging.getLogger(__name__)

def normalizar_pdf(archivo_obj: Path, pdf_stream: BytesIO) -> Path | None:
    # lo crea en el mismo directorio donde existe el anterior y retorna el str de ruta os del nuevo
    nuevo = Path(f"{archivo_obj.parent}/{archivo_obj.stem}_NORMALIZADO{archivo_obj.suffix}")

    try:
        original_normalizado = pike_open(filename_or_stream=pdf_stream)
        original_normalizado.save(filename_or_stream=nuevo)
    except Exception:
        logger.error("No pudo normalizarse PDF: %s. Saliendo...", nuevo.name)
        return None
    else:
        print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Válido: {nuevo.name}")
        return nuevo

@salida_limpia()
def pre_firma(lista_pdfs: list) -> list | bool:
    '''
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
    '''

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

    dummy_signer = signers.SimpleSigner(
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

    logger.info("Evaluando la integridad de los PDFs...")
    for i in lista_pdfs:
        dummy_stream = BytesIO()

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
        siguiente_firma = 0

        with open(f'{i}', 'rb') as f_stream:
            original = PdfFileReader(f_stream)
            siguiente_firma = len(original.embedded_signatures)

        with open(f'{i}', 'rb') as f_stream:
            original = IncrementalPdfFileWriter(f_stream)
            try:
                signers.sign_pdf(
                    pdf_out=original,
                    output=dummy_stream,
                    signer=dummy_signer,
                    signature_meta=dummy_sig_meta,
                    timestamper=None,
                    new_field_spec=None,
                    existing_fields_only=False,
                )
            
            # Excepts de errores relacionados con PDFs. (SigningError, UnicodeDecodeError)
            except Exception as e:
                logger.warning("Invalido: %s (%s)", i.name, e)
                logger.warning("Puede corregir creando un PDF *nuevo* con el contenido visual del original y firmar ese en su lugar.\n")

                while True:
                    opcion = input(f'Reparar {i.name}? (y/n): ')
                    if opcion == 'y' :
                        print('Reparando...\n')
                        break
                    elif opcion == 'n':
                        print(f"No es posible firmar en este estado. Saliendo...")
                        return False
                    else:
                        print('Ingrese una opción correcta.')

                nuevo_path = normalizar_pdf(archivo_obj=i, pdf_stream=f_stream)
                if nuevo_path == False:
                    return False

                else:
                    # Cuando se normalice un PDF con errores se incrustará el archivo nuevo normalizado (objeto Path)
                    # en el índice del archivo que tuvo problemas al pre-firmar; sustituyendolo en su mismo indice
                    # y así retornar una lista consistente con el órden inicial en el que se instanciaron los objetos
                    # Path, objetos Path que apuntarán a archivos reales y válidos para firmar.

                    if nuevo_path in lista_pdfs:
                        lista_pdfs.pop(lista_pdfs.index(nuevo_path))

                    indice = lista_pdfs.index(i)
                    lista_pdfs[indice] = (nuevo_path, siguiente_firma) # sustituye con tupla: (PDF normalizado, siguiente indice de firma)

            else:
                indice = lista_pdfs.index(i)
                lista_pdfs[indice] = (i, siguiente_firma) # sustituye con tupla: (PDF original, siguiente indice de firma)

                print(f'[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Válido: {i.name}')

                # La sustitución con indices a mi juicio parece salvaje, pero en principio se sustenta en el
                # comportamiento normal de cualquier directorio; donde no se puede tener (en el mismo directorio)
                # más de 1 archivo con el mismo nombre.

                # Se entiende que si todos los PDFs existentes en ruta base tienen nombre diferente entonces
                # todos los resultados de .index(i) en 'indice' serán diferentes y por ende no se sutituirá
                # equivocadamente un PDF distinto al pretendido por haber sido "el primero encontrado".

                # Para el caso: "if nuevo_path in lista_pdfs:" en bloque de normalizados.
                # Dado que los normalizados se alamcenan en ruta base, y se prefiere NO eliminarlos después de una
                # sesión donde se hayan tenido que crear, se entiende que: si en una sesión de firma posterior a
                # una con PDFs normalizados se intentase 're-firmar' un pdf normalizado existente en la ruta base
                # (por no haberlo eliminado a mano o movido de directorio) este se popeará de la lista inicial
                # generada desde ruta base para evitar inconvenientes.

    print(f'\n[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Material para firmar ({len(lista_pdfs)}) listo.')
    print()
    return lista_pdfs

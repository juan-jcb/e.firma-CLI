import logging
from io import BytesIO, BufferedReader
from pathlib import Path
from colorama import Fore

logging.getLogger("pikepdf").setLevel(logging.WARNING) # pikepdf gestiona su propio logger, mejor silenciar su INFO y usar solo warning
logging.getLogger("pyhanko.pdf_utils.xref").setLevel(logging.ERROR) # [WARNING] Superfluous whitespace found in object header 3 0
from pikepdf import open as pike_open

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

from pyhanko.sign.general import SigningError
from pyhanko.pdf_utils.misc import PdfReadError, PdfStrictReadError
from pyhanko.pdf_utils.metadata.xmp_xml import XmpXmlProcessingError
#from pyhanko.pdf_utils.crypt.api import PdfKeyNotAvailableError # seguro que aparece en algún momento.

from efcli.core.core_utils import get_dummy_signer
from efcli.core.wrappers import salida_limpia

logger = logging.getLogger(__name__)

def normalizar_pdf(pdf: Path, autoconfirmar: bool) -> tuple[Path, BufferedReader, PdfFileReader, IncrementalPdfFileWriter] | None:
    """
    Normaliza un PDF malformado o con errores de lectura (prompt interactivo).
    Crea un nuevo archivo PDF en base al original en su misma ruta con un sufijo
    diferenciador.

    :param pdf:
        `Path` del PDF a normalizar.

    :return:
        `tuple` con 4 elementos:
            idx 0: `Path` del PDF nuevo normalizado con el sufijo extendido "_NORMALIZADO" en la misma ruta de `pdf`.
            idx 1: `BufferedReader` ABIERTO del PDF nuevo normalizado (debe cerrarse explicitamente cuando ya no se requiera)
            idx 2: `PdfFileReader` del PDF normalizado.
            idx 3: `IncrementalPdfFileWriter` del PDF normalizado.
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
        normalizado_stream = open(f'{normalizado_path}', 'rb')
        normalizado_lector = PdfFileReader(normalizado_stream)
        normalizado_escritor = IncrementalPdfFileWriter(normalizado_stream)
        return (normalizado_path, normalizado_stream, normalizado_lector, normalizado_escritor)

@salida_limpia()
def prefirmar(lista_pdfs: list, autoconfirmar: bool) -> tuple[list, list] | bool:
    """
    Función de comprobación sobre la viabilidad de firma en el/los PDFs originales.
    Se realiza una firma básica 'PAdES-B-B' en memoria instanciando a un firmante
    genérico.

    Esta función tiene como finalidad comprobar la integridad de el/los PDFs originales
    y determinar si son aptos para procesarse con pyhanko previo a las firmas reales
    que sí se almacenan.

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
        `tuple` con 2 elementos:

        idx 0: `list` con 3 elementos:
            idx 0: objeto `Path` (normalizado o no) del .pdf a firmar.
            idx 1: `bool` indicativo de uso de cifrado en el PDF procesado.
            idx 2: `int` incativo de "la siguiente firma" que será incrustada en PDF

        idx 1: `list` con todos los PDFs normalizados (si los hay), puede ser también
        lista vacia.
    """
    DUMMY_SIGNER = get_dummy_signer()
    L_PROPUESTOS: int = len(lista_pdfs)
    NORMALIZADOS = []
    ELIMINADOS = []
    PARA_ITERAR = lista_pdfs.copy() # dado que lista_pdfs es mutada durante iteración se requiere una copia no mutable

    logger.info("Evaluando integridad de los PDFs propuestos (%s)...\n", L_PROPUESTOS)
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
    for i in PARA_ITERAR:
        lector = None
        escritor = None
        normalizado_path = None
        normalizado_stream = None
        esta_cifrado = False
        siguiente_firma = 0
        idx_pdf_actual = lista_pdfs.index(i)

        with open(f'{i}', 'rb') as f_stream:
            header = f_stream.read()[:5] # Evaluar en primer lugar que el archivo sea un PDF real (no provoca error si es archivo vacio o menor a 5 bytes).

            try:
                lector = PdfFileReader(f_stream)

            except (PdfReadError, PdfStrictReadError) as e:
                if header != b'\x25\x50\x44\x46\x2D': # Header PDF (%PDF-) independiente de la versión.
                    print()
                    logger.error("NO ES UN PDF: '%s' (%s)", i.name, e)
                    logger.error("Se omitirá éste archivo y se continuará sin él.\n")
                    ELIMINADOS.append(i)
                    lista_pdfs.pop(idx_pdf_actual)
                    continue

                    # TODO: Es factible que existan PDFs reales con cabecera "ilegal", los cuales; parsers permisivos
                    # podrán leer, pero ésta evaluación explicita contra el header los descarte como: "No es un PDF".
                    # Yo prefiero seguir el parseo estricto de pyhanko para calificar dichos casos como "no validos",
                    # aunque puedan ser técnicamente legibles y normalizables. Quedará a criterio que tan quisquilloso
                    # se quiera ser sobre la validación de cada PDF ya que este escenario se puede dar en alguna que
                    # otra ocasión.

                print()
                logger.warning("Lectura inicial INCONSISTENTE: %s (%s)", i.name, e)
                normalizado_path, normalizado_stream, lector, escritor = normalizar_pdf(pdf=i, autoconfirmar=autoconfirmar)
                i = normalizado_path

            try:
                if lector.encrypted:
                    esta_cifrado = True
                    # Salvaje pero de momento temporal, asumimos que entró en este bloque sin errores de carga inicial y está cifrado
                    logger.warning("PDF CIFRADO: '%s'", i.name)
                    logger.info("Descifrando con cadena vacia...")
                    lector.decrypt(password="") # vaya nombres raros para hacer lo mismo
                    siguiente_firma = len(lector.embedded_signatures)
                    if not escritor:
                        escritor = IncrementalPdfFileWriter(f_stream)
                        escritor.encrypt(user_pwd="") # vaya nombres raros para hacer lo mismo

            except PdfReadError as e:
                logger.warning("PDF cifrado SIN referencia indirecta: '%s' (%s)", i.name, e)
                normalizado_path, normalizado_stream, lector, escritor = normalizar_pdf(pdf=i, autoconfirmar=autoconfirmar)
                i = normalizado_path
                if lector.encrypted:
                    esta_cifrado = True

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
                normalizado_path, normalizado_stream, lector, escritor = normalizar_pdf(pdf=i, autoconfirmar=autoconfirmar)
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
                normalizado_path, normalizado_stream, lector, escritor = normalizar_pdf(pdf=i, autoconfirmar=autoconfirmar)
                # Caso particular: pdf que se normaliza después de pre-firma. Se necesita confirmación explicita
                # de que todos los PDFs normalizados son firmables por lo que se vuelve a firmar.
                try:
                    DUMMY_SIGNER.sign_pdf(
                        pdf_out=escritor,
                        output=BytesIO(),
                        existing_fields_only=False,
                    )
                except Exception as e:
                    logger.critical("Error en firma post-normalización. (%s)", e)
                    print("Saliendo...")
                    exit()
                else:
                    i = normalizado_path

            finally:
                if (normalizado_path and normalizado_stream):
                    normalizado_stream.close()
                    NORMALIZADOS.append(normalizado_path)

                    # Esta evaluación es contradictoria, pero es para los casos limite donde la normalización de
                    # un PDF cifrado se lo termina quitando. (estaba cifrado, se normalizó, dejo de estár cifrado)
                    # si la flag boolena no se actualiza se asumiría existencia de security handler en firma final
                    # cuando a causa de la normalización dejó de existir (pasa a NoneType) y causa error.
                    if esta_cifrado == True and not lector.encrypted:
                        logger.debug("La normalización del PDF le sacó el cifrado (%s)", normalizado_path)
                        esta_cifrado = False

                print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Válido: '{i.name}'")
                lista_pdfs[idx_pdf_actual] = (i, esta_cifrado, siguiente_firma)
                # Cuando se normalice un PDF con errores se incrustará el archivo nuevo normalizado (objeto Path)
                # en el índice del archivo que tuvo problemas al pre-firmar; sustituyendolo en su mismo indice
                # y así retornar una lista consistente con el órden inicial en el que se instanciaron los objetos
                # Path, objetos Path que apuntarán a archivos reales y válidos para firmar.
                # La sustitución con indices a mi juicio parece salvaje, pero en principio se sustenta en el
                # comportamiento normal de cualquier directorio; donde no se puede tener (en el mismo directorio)
                # más de 1 archivo con el mismo nombre. Se entiende que si todos los PDFs existentes en ruta
                # base tienen nombre diferente entonces todos los resultados de .index(i) en 'idx_pdf_actual'
                # serán diferentes y por ende no se sutituirá equivocadamente un PDF distinto al pretendido por
                # haber sido "el primero encontrado".

    if len(lista_pdfs) >= 1:
        print()
        logger.info("Material inicial evaluado correctamente.")

        if NORMALIZADOS:
            print(f"     • PDFs propuestos: {L_PROPUESTOS}")
            print(f"     • PDFs normalizados: {len(NORMALIZADOS)}")
        if ELIMINADOS:
            print(f"     • Omitidos por inviabilidad: {len(ELIMINADOS)}")
        print(f"     • Listos para firmar: {len(lista_pdfs)}\n")

        return (lista_pdfs, NORMALIZADOS)

    else:
        logger.warning("No hay suficiente material para firmar. Saliendo...")
        exit()

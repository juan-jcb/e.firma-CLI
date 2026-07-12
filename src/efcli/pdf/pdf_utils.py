import logging
from io import BytesIO, BufferedReader
from pathlib import Path

logging.getLogger("pikepdf").setLevel(logging.WARNING) # pikepdf gestiona su propio logger, mejor silenciar su INFO y usar solo warning
logging.getLogger("pyhanko.pdf_utils.xref").setLevel(logging.ERROR) # [WARNING] Superfluous whitespace found in object header 3 0
from pikepdf import open as pike_open

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation.dss import DocumentSecurityStore

from efcli.core import cripto, x509

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

def leer_firmas_pdf(pdf_input: str | BytesIO, usa_cifrado: bool = False) -> list[str]:
    """
    Lee las firmas incrustadas en un archivo pdf, diferenciando por tipo
    /Sig y /DocTimeStamp.

    :param pdf_input:
        `BytesIO` del archivo pdf o `str` de ruta tipo OS hacia el archivo pdf.

    :return:
        `list` de `str` con desglose textual simple:
            
            ["CN \\<email\\> (Serial) (Tipo)", "..."]
        
        de las firmas encontradas en el orden que se realizaron. Lista vacia
        si no tiene firmas.
    """

    # Normalización previa a operar solo con BytesIO
    if isinstance(pdf_input, str):
        try:
            with open(pdf_input, "rb") as f:
                pdf_input = BytesIO(f.read())
        except FileNotFoundError:
            raise ValueError("Archivo no encontrado:", pdf_input)

    pdf_reader = PdfFileReader(pdf_input)

    # TODO: no me termina de agradar. asumimos que el cifrado es "password permissions" que se "libera" con caden vacia
    if usa_cifrado:
        pdf_reader.decrypt(password="")

    firmas = []
    firmas_etiquetadas = []
    etiquetas = {
        0: "Regular",
        1: "Timestamp",
    }

    # listas de objetos: pyhanko.sign.validation.pdf_embedded.EmbeddedPdfSignature
    total_firmas = pdf_reader.embedded_signatures
    regulares = pdf_reader.embedded_regular_signatures
    incrementales = pdf_reader.embedded_timestamp_signatures

    # Re-etiquetado de las firmas hechas para saber de qué lista provienen. Se entiende "embedded_signatures"
    # como array maestro lineal y "embedded_regular_signatures", "embedded_timestamp_signatures" como particiones.
    # Lo que se busca es re-etiquetar ordenadamente en una nueva lista los elementos desde las particiones e
    # incluír una señalización explicita sobre la lista de la que cada uno proviene originalmente, lo que se
    # traduce funcionalmente al 'tipo de firma' que es cada firma: regular o timestamp.

    #arr =  [1,2,3,4,5,6,7,8,9]
    #arr1 = [1,2,4,5,6,9]
    #arr2 = [3,7,8]
    #arr3 = []
    # [("a1", 1), ("a1", 2), ("a2", 3), ("a1", 4), ("a1", 5), ("a1", 6), ("a2", 7), ("a2", 8), ("a1", 9)]

    # caso 1. no hay elementos en ninguna partición
    if not regulares and not incrementales:
        pass

        # TODO:
        # En el flujo normal del programa esto nunca ocurre ya que siempre se firma y luego se cuentan
        # las firmas, indpendientemente de si el PDF original no tenía ninguna firma, por lo que el caso:
        # "no hay elementos en ninguna partición" no se da.
        # Sin embargo si en el futuro se usa esta función por fuera del flujo normal del programa, entonces
        # si se leeyese un PDF sin firmas ahora sí entra en este bloque y provoca error abajo.

    # caso 2. hay elementos en ambas particiones
    elif regulares and incrementales:
        idx1 = 0
        idx2 = 0
        for i in total_firmas:
            if i == regulares[idx1]:
                firmas_etiquetadas.append((i, etiquetas[0]))
                idx1 += 1
                if idx1 == len(regulares): # no me agrada para evitar errores de 'sumó a un indice inexistente' pero eh, funciona ¯\_(ツ)_/¯
                    idx1 -= 1
            elif i == incrementales[idx2]:
                firmas_etiquetadas.append((i, etiquetas[1]))
                idx2 += 1
                if idx2 == len(incrementales):
                    idx2 -= 1

    # caso 3. hay elementos en almenos 1 partición, ergo el array maestro y la partición con datos tienen
    # exactamente los mismos elementos.
    elif regulares or incrementales:
        if regulares:
            tag = etiquetas[0]
        if incrementales:
            tag = etiquetas[1]

        firmas_etiquetadas = [(i, tag) for i in total_firmas]

    #for i in range(0, len(total_firmas)): # técnicamente es lo mismo dado que se vuelve a llenar con la misma cantidad de elementos
    for i in range(0, len(firmas_etiquetadas)):
        firma = firmas_etiquetadas[i][0]
        tipo = firmas_etiquetadas[i][1]

        # TODO: asumimos mucho, pero de momento funciona.
        if tipo == etiquetas[0]: # Regular
            if cripto.extraer_tst_cms(cms=firma.pkcs7_content, signer=0, contrafirma=0):
                tipo = "Regular + Timestamp"

        firmas.append(f"{x509.leer_subject_simple(cert=firma.signer_cert)} ({tipo})")

    return firmas

def extraer_cms_y_vri(stream, indice: int, usa_cifrado: bool = False) -> tuple[bytes, str]:
    """
    Extraer contenedor CMS de un PDF (evidentemente ya firmado) en base al
    orden representado en indices de firmas ya existentes en el propio PDF.

    :param stream:
        Objeto `BytesIO` del contenido de un PDF ya firmado.
    
    :param indice:
        Índice de la firma a procesar (0, 1, 2, 3, 4 ...)
    
    :return:
        `tuple` con 2 elementos `bytes` y `str`: (cms_en_bytes, entrada_vri_str)
    """
    firmado_reader = PdfFileReader(stream)
    # TODO: no me termina de agradar. asumimos que el cifrado es "password permissions" que se "libera" con caden vacia
    if usa_cifrado:
        firmado_reader.decrypt(password="")

    firmas_incrustadas = firmado_reader.embedded_signatures
    if not firmas_incrustadas:
        raise ValueError("El PDF no contiene firmas digitales")
    firma_obj = firmas_incrustadas[indice]
    cms_bytes = firma_obj.pkcs7_content           # Firma CMS completa (en bytes)
    #cms_bytes = firma_obj.sig_object['/Contents'] # También Firma CMS completa (en bytes) (no funciona con pdfs cifrados en owner/permissions)
    vri = DocumentSecurityStore.sig_content_identifier(cms_bytes)

    return (cms_bytes, vri)

def leer_dss(ruta_pdf: str):
    with open(ruta_pdf, 'rb') as f:
        reader = PdfFileReader(f)

        try:
            dss = DocumentSecurityStore.read_dss(reader)
            if dss:
                print("[OK] DSS Encontrado.")
                print(f"VRI entries: {len(dss.vri_entries)}")
                print(f"Certs en DSS: {len(dss.certs)}")
                print(f"Respuestas OCSP en DSS: {len(dss.ocsps)}")

                for i in dss.vri_entries:
                    print('\n=== Entradas VRI ===')
                    print(i)

            else:
                print(f"[ERROR] No se encontró DSS en el PDF {ruta_pdf}")

        except Exception as e:
            print(f"Error al leer DSS: {e}")

def agregar_dss(pdf_input: str, pdf_output: str, firma_bytes: bytes, ocsp_resp):
    # Añadir contexto asociado a una entrada VRI en el DSS del pdf: objeto respuesta OCSP,
    # certificado del firmante, cadena de confianza (tipicamente sin raíz), etc.        
    with open(pdf_input, 'rb') as f:
        writer = IncrementalPdfFileWriter(f)

        dss = DocumentSecurityStore.supply_dss_in_writer(
            pdf_out=writer,
            sig_contents=firma_bytes,    # crea la entrada VRI en base a la firma: hashlib.sha1(sig_contents).digest().hex().upper()
            ocsps=[ocsp_resp],
            #certs=None,                 # certificados si se tienen
            #crls=None,                  # CRLs si se tienen
        )

        with open(pdf_output, 'wb') as f_out:
            writer.write(f_out)

        # supply_dss_in_writer() opera sobre el objeto pdf_writer que se le pasa como argumento
        # con pdf_out=. El valor de retorno (DocumentSecurityStore) queda disponible en dss por
        # si se necesita inspeccionar el estado resultante del DSS, pero su uso es opcional y en
        # la mayoría de los flujos se descarta.    
        # supply_dss_in_writer() modifica pdf_writer en memoria, pdf_writer.write(out_f) serializa
        # ese contenido; el PDF original + la actualización incremental con el DSS hacia el flujo
        # de bytes 'f_out', que se almacena en el archivo 'pdf_output'.        
        # El PDF original instanciado como IncrementalPdfFileWriter no se modifica en ningún momento.
        # La estructura del DSS se añade como nueva revisión al final del documento de salida,
        # requisito escencial para no invalidar las firmas preexistentes.
        # Este método ya maneja el hasheo y formato para VRI desde los bytes de la firma en
        # binario dada en'sig_contents='

    print(f"DSS actualizado para: {pdf_input}")
    print(f"PDF resultante en: {pdf_output}")
    return True

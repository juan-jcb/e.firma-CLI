from pathlib import Path
from io import BytesIO

from pyhanko.sign import timestamps
from pyhanko.sign.signers import PdfTimeStamper
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

def hacer_tst(pdf_input: str, tsa_url: str, hash_algo: str) -> bool:
    '''
    Añade un TST incremental en el /DocTimeStamp de un PDF.
    '''

    if isinstance(pdf_input, str):
        nombre = Path(pdf_input)
        try:
            with open(pdf_input, "rb") as f:
                pdf_input = BytesIO(f.read())

        except FileNotFoundError:
            raise ValueError("Archivo no encontrado:", pdf_input)

    writer = IncrementalPdfFileWriter(pdf_input)
    ts = PdfTimeStamper(timestamper=timestamps.HTTPTimeStamper(url=tsa_url))

    try:
        with open(f'{nombre.stem}_timestamped{nombre.suffix}', 'wb') as f:
            ts.timestamp_pdf(
                pdf_out=writer,
                output=f,
                md_algorithm=hash_algo,
            )

    except Exception as e:
        print(f"Error al añadir Timestamp Token incremental: {e}")
        return False
    else:
        return True

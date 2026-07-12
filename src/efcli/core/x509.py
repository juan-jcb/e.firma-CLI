from pathlib import Path
from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives.serialization import Encoding

def leer_campo_en_subject(subject, campo: str) -> str:
    for rdn in subject.chosen:
        for atv in rdn:
            if atv["type"].native == campo:
                return atv["value"].native
    return ""

def leer_subject_simple(cert: asn1_x509.Certificate) -> str:
    """
    Lee los datos más relevantes de un certificado X.509.

    :param cert:
        Objeto `asn1crypto.x509.Certificate`

    :return str:
        texto con la forma: **"CN \\<mail\\> (Serial)"**
    """
    serial_asn1 = cert.serial_number
    serial_hex = format(serial_asn1, 'x').upper()
    if len(serial_hex) % 2:
        serial_hex = "0" + serial_hex
    try:
        serial_sat = f"Serial SAT: {bytes.fromhex(serial_hex).decode('ascii')}"
    except UnicodeDecodeError:
        serial_hex_colon = ':'.join(serial_hex[k:k+2] for k in range(0, len(serial_hex), 2))
        serial_sat = f"Serial x509: {serial_hex_colon}"

    cn = leer_campo_en_subject(subject=cert.subject, campo="common_name")
    email = leer_campo_en_subject(subject=cert.subject, campo="email_address")

    # Fallback para buscar en SAN si no hay email en subject
    if not email:
        try:
            for san in cert.subject.subject_alt_name_value:
                if san.name == "rfc822_name":
                    email = san.chosen.native
        except AttributeError, TypeError:
            email = "Sin Mail"

    return f"{cn} <{email}> ({serial_sat})"

def cargar_cert_asn1(cert: str | Path | bytes) -> tuple[asn1_x509.Certificate, str]:
    """
    Carga un certificado X.509 emitido por el SAT como objeto
    `asn1crypto.x509.Certificate`.

    Debido a que la autoridad certificadora de Banxico no utiliza OIDs
    estandar en sus x509 se requiere utilizar parsers más 'amigables'
    antes de cargar a los objetos que realizan operaciones con estos
    (la función normaliza certificados x509 para saltarse el error de
    carga inicial con asn1crypto).

    :param cert:
        `str` o `Path` de ruta OS del archivo certificado, o `bytes`
        directos del certificado a normalizar (ambos encode DER/PEM).

    :return tuple:
        tupla con objeto `asn1crypto.x509.Certificate` del x509 en
        cuestión y `str` mayus con el tipo de encode que utiliza (DER/PEM).
    """
    # gestión para recibir tanto bytes como str de rutas OS del certificado.
    if isinstance(cert, str) or isinstance(cert, Path):
        try:
            with open(cert, 'rb') as b:
                cert_bytes = b.read()
        except FileNotFoundError:
            raise ValueError("Archivo no encontrado:", cert)
    elif isinstance(cert, bytes):
        cert_bytes = cert

    # Cargar primero con cryptography por parseo permisivo; primero DER (más común), luego PEM.
    try:
        crypto_cert = crypto_x509.load_der_x509_certificate(data=cert_bytes)
        cert_encode = "DER"
    except Exception:
        crypto_cert = crypto_x509.load_pem_x509_certificate(data=cert_bytes)
        cert_encode = "PEM"

    # El objeto certificado de cryptography se serializa a bytes DER y s carga como objeto
    # 'asn1crypto.x509.Certificate'. public_bytes() en Encoding DER es exactamente lo que
    # remueve el error. ValueError: Error parsing asn1crypto.x509.Certificate - tag should have been 16, but 13 was found
    asn1_cert = asn1_x509.Certificate.load(encoded_data=crypto_cert.public_bytes(encoding=Encoding.DER))
    return (asn1_cert, cert_encode)

"""
Scripts para pruebas de validez operativa de certificados x509 del SAT debido
a que si los certificados usasen formatos ASN.1 estándar ambas pruebas con
cryptography y asn1crypto no deberían de mostrar ningún error, pero aquí estamos :p
"""

def recorrer_oids(cert) -> None:
    """
    Función para recorrer los OIDs del subject/issuer de un x509 del
    SAT (instanciado como objeto asn1crypto.x509.Certificate)

    Está diseñada para visualizar explicitamente el error de codificación
    de los certificados del SAT en el campo: x500UniqueIdentifier=

        ValueError: Error parsing asn1crypto.core.OctetBitString - tag should have been 3, but 19 was found
        while parsing asn1crypto.x509.NameTypeAndValue

    Certificados Raíz de Banxico no lo poseen (al parecer) pero CAs
    intermedias y certificados de cliente si lo tienen.
    Ejemplo CA intermedia SAT:

        00000110: 4d4f 4331 1530 1306 0355 042d 130c 5341  MOC1.0...U.-..SA
        00000120: 5439 3730 3730 314e 4e33 315c 305a 0609  T970701NN31\0Z..

    OID mal codificado:

        00000110:             30 1306 0355 042d 130c 5341  MOC1.0...U.-..SA
        00000120: 5439 3730 3730 314e 4e33                 T970701NN31\0Z..

        30 13          							# SEQUENCE de 19 bytes (RDN)
        06 03 55 04 2d    						# OID: 2.5.4.45 (x500UniqueIdentifier)
        13 0c             						# Tag 0x13 (19) = PrintableString de 12 bytes
        53 41 54 39 37 30 37 30 31 4e 4e 33  	# "SAT970701NN3"

    Parche momentaneo:

        asn1crypto/x509.py, diccionario "_oid_specs", linea 677:

        Cambiar de:     'unique_identifier': OctetBitString,
        A:              'unique_identifier': DirectoryString,
    """

    print(f"\n{'='*80}\n")

    # cambiar entre subject e issuer en el objeto cert
    for i, rdn in enumerate(cert.issuer.chosen):
    #for i, rdn in enumerate(cert.subject.chosen):
        print(f"RDN #{i+1}:")
        for j, attr in enumerate(rdn):
            oid = attr['type'].dotted
            print(f"  Atributo #{j+1}: OID = {oid}")
            print(f"    Nombre del OID: {attr['type'].native if attr['type'].native else 'DESCONOCIDO'}")
            
            # Intentar acceder al valor de diferentes maneras
            value_obj = attr['value']
            print(f"    Tag ASN.1 del valor: {value_obj.tag}")
            print(f"    Clase del objeto valor: {value_obj.__class__.__name__}")
            
            # Intento 1: Acceder a .native
            try:
                print(f"    Valor (.native): {value_obj.native}")
            except Exception as e:
                print(f"    ERROR al acceder a .native: {e}")
                
            # Intento 2: Ver los bytes crudos
            try:
                print(f"    Bytes: {value_obj.dump().hex()}")
            except:
                print(f"    No se pudieron obtener bytes crudos")
            
            # Si el OID es unstructuredName, analizamos más
            if oid == "1.2.840.113549.1.9.2":
                print(f"    *** Este es unstructuredName ***")
                print(f"    Tag esperado: 19 (PrintableString) o 20 (TeletexString)")
                print(f"    Tag encontrado: {value_obj.tag}")
                
            print()

    # Comparación con issuer
    print("=== COMPARATIVA CON ISSUER ===\n")
    for rdn in cert.issuer.chosen:
        for attr in rdn:
            if attr['type'].dotted == "1.2.840.113549.1.9.2":
                print(f"Issuer unstructuredName - Tag: {attr['value'].tag}")
                try:
                    print(f"Issuer unstructuredName - Valor: {attr['value'].native}")
                except:
                    print("Issuer también falla (inesperado)")

from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_private_key, load_pem_private_key
from asn1crypto.cms import ContentInfo
#from asn1crypto.tsp import TSTInfo

def es_pkey_cifrada(ruta_pkey: str | Path) -> tuple[bool, str]:
    """
    Determina si una pkey está cifrada, además del tipo de encode que usa:
    DER o PEM.

    :param ruta_pkey:
        `str` o `Path` de ruta del archivo pkey.

    :return tuple:
        Tupla (para desempaquetar) con 2 elementos: `bool` de respuesta
        y `str` indicando el tipo de encode, ej: (True, "DER"), (False, "PEM")
    """
    with open(ruta_pkey, 'rb') as b:
        data = b.read()

    # Primero intenta cargar en DER; encode que entrega el SAT para las claves,
    # y que en principio debería de entrar siempre a la función dado que la
    # mayoría de la bandita no lo cambia.
    try:
        load_der_private_key(data=data, password=None)
    except TypeError:
        return (True, "DER")

    # Si algún cabeza lista ya pasó su pkey a PEM se gestiona tal que si exceptua
    # "ValueError" la clave entonces es PEM.
    except ValueError:
        try:
            load_pem_private_key(data=data, password=None)
        except TypeError:
            return (True, "PEM")
        else:
            return (False, "PEM")
    else:
        return (False, "DER")

def es_passwd_de_pkey(ruta_pkey: str | Path, tipo_encode: str, passwd: str) -> bool:
    """
    Confirma si la passphrase de una determinada pkey puede descifrarla. Usar
    después de `es_pkey_cifrada()` para pasar correctamente el tipo de encode.

    :param ruta_pkey:
        `str` o `Path` de ruta del archivo pkey.
    
    :param passwd:
        `str` a probar como passphrase de la pkey.
    
    :param tipo_encode:
        `str` mayús indicando el tipo de encode que usa la clave: "DER", "PEM"

    :return bool:
        `True` si passwd descifra, `False` en caso contrario.
    """
    with open(ruta_pkey, 'rb') as b:
        data = b.read()

    if tipo_encode == "DER":
        func = load_der_private_key 
    elif tipo_encode == "PEM":
        func = load_pem_private_key 

    try:
        func(data=data, password=passwd)
    except TypeError, ValueError:
        return False
    else:
        return True

def bytes_publicos_rsa(ruta_pkey: str | Path, encode: str = "DER", password: bytes = None) -> bytes:
    """
    Retorna los bytes de una clave pública RSA desde la clave privada.
    
    Se asume que cuando se llama a ésta función ya se ha determinado
    encode y contraseña.

    :param ruta_pkey:
        `str` o `Path` de ruta del archivo pkey.

    :param tipo_encode:
        `str` mayús indicando el tipo de encode que usa la clave: "DER", "PEM".
        Por defecto "DER"
    
    :param password:
        `bytes` de la contraseña a utilizar para descifrar la clave privada.
        Por defecto `None`

    """
    with open(ruta_pkey, 'rb') as b:
        data = b.read()

    if encode == "DER":
        pkey = load_der_private_key(data=data, password=password)
    elif encode == "PEM":
        pkey = load_pem_private_key(data=data, password=password)

    return pkey.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.PKCS1)

def extraer_tst_cms(cms: bytes, signer: int, contrafirma: int) -> bytes | None:
    """
    Extrae un 'TST' anidado en las contrafirmas de N 'SigerInfo' en un 'CMS'.
    """
    contenedor = ContentInfo.load(encoded_data=cms)

    unsignedAttrs = contenedor["content"]["signer_infos"][signer]["unsigned_attrs"]
    if not unsignedAttrs:
        return None # El firmante no tiene de unsigned_attrs, no puede haber contrafirmas.

    for i in unsignedAttrs:
        #if j["type"].native == "signature_time_stamp_token":
        if i["type"].dotted == "1.2.840.113549.1.9.16.2.14":
            return i["values"][contrafirma].dump()
            #return i["values"][contrafirma]["content"]["encap_content_info"]["content"].contents # Solo bytes der de TSTInfo

def extraer_tstinfo(tst: bytes) -> bytes | None:
    """
    Extrae el 'TSTInfo' de un 'TST' (Su 'Encapsulated Content Info').
    """
    contenedor = ContentInfo.load(encoded_data=tst)
    #if contenedor["content"]["encap_content_info"]["content_type"].native == "tst_info":
    if contenedor["content"]["encap_content_info"]["content_type"].dotted == "1.2.840.113549.1.9.16.1.4":
        return contenedor["content"]["encap_content_info"].contents
    else:
        return None

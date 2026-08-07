from pathlib import Path
from datetime import datetime, timedelta

from asn1crypto import x509 as asn1_x509
from asn1crypto import keys as asn1_keys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

from pyhanko.sign import signers, fields

def continuar_salir(msj: str):
    """
    Prompt mínimo de confirmación (y/n) para continuación o salida
    del programa. Acepta input vacio como sinonimo de 'y'.
    """
    while True:
        opcion = input(msj)
        if (opcion == 'y') or (opcion == ''):
            print("Continuando...")
            break
        elif opcion == 'n':
            print("Saliendo...")
            exit()
        else:
            print('Ingrese una opción correcta.')
    
    return True # para usar ambos: fn() o 'if fn()'

def continuar_salir_msj(msj: str, si_continua: str, si_sale: str):
    """
    Prompt mínimo de confirmación (y/n) para continuación o salida
    del programa. Usar cuando se requiere extender sobre el contexto
    del mensaje de continuación. El input debe ser solo 'y' o 'n'.
    """
    while True:
        opcion = input(msj)
        if opcion == 'y':
            print(si_continua)
            break
        elif opcion == 'n':
            print(si_sale)
            exit()
        else:
            print('Ingrese una opción correcta.')

    return True


def guardar_archivos(*args, **kwargs) -> None:
    """
    Función generalizada para almacenar archivos en X ruta
    asumiendo que el contenido a almacenar existe y es bytes.

    La lógica de ruta, extensión y número de archivos se
    determina según la organización de los argumentos en
    la llamada.

    :param args:
        Indice 0: :class:`str` de ruta en sistema. Si ruta no
        existe se crean directorios intermedios, si ya existe
        se usa ese sin sobreescribir.

        Indice 1: :class:`str` para extensión de archivo (sin `.`)

    :param kwargs:
        Pares "clave:valor" donde `clave` es nombre del archivo
        y `valor` son los :class:`Bytes` a escribir.
    """
    ruta = Path(args[0])
    ext = args[1]

    if not ruta.is_dir():
        ruta.mkdir(parents=True)
    for i, j in kwargs.items():
        with open(f'{ruta}/{i}.{ext}', 'wb') as b:
            b.write(j)

def get_dummy_signer() -> signers.PdfSigner:
    """
    Instancia un firmante genérico `PdfSigner` con certificado X.509
    autofirmado y clave RSA de 2048 bits.
    """
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

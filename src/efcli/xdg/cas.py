'''
Módulo especifico para la gestión de PKI externa que se importa al entorno XDG de efcli.

Aunque efcli lo denomina organizacionalmente como "submodulo PKI", la jerarquia de éste código aplica
para ser modulo especifico del paquete XDG ya que las operaciones aqui desarrolladas DEPENDEN de que
exista un entorno XDG inicializado para importar PKIs externas e interactuar con ellas.
'''
import logging, json
from pathlib import Path

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from asn1crypto import pem

from efcli.core import core_utils, wrappers, x509, regex
from . import xdg_config
from .bootstrap import check_env

logger = logging.getLogger(__name__)

@wrappers.salida_limpia()
@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def add_ca(cafile: str) -> None:
    '''
    Añade una CA externa a las entidades de confianza del programa desde su bundle PEM.
    (prompt interactivo)
    '''
    ca_certs = []
    ca_names = []
    ca_pem_strings = b''
    with open(cafile, 'rb') as f:
        b = f.read()

    try:
        if b[:27] == b'-----BEGIN CERTIFICATE-----':
            c = crypto_x509.load_pem_x509_certificates(data=b)
        else:
            c = crypto_x509.load_der_x509_certificate(data=b)
    except Exception as e:
        logger.error("El archivo no es un certificado x509, intentelo de nuevo (%s)", e)
        exit()

    else:
        if isinstance(c, list):
            for i in c:
                crt = i.public_bytes(encoding=serialization.Encoding.DER)
                ca_names.append(x509.leer_subject_simple(cert=x509.cargar_cert_asn1(cert=crt)[0]))
                ca_pem_strings += pem.armor(der_bytes=crt, type_name="CERTIFICATE")
        else:
            crt = c.public_bytes(encoding=serialization.Encoding.DER)
            ca_names.append(x509.leer_subject_simple(cert=x509.cargar_cert_asn1(cert=crt)[0]))
            ca_pem_strings = pem.armor(der_bytes=crt, type_name="CERTIFICATE")

        ca_certs += [x509.cargar_cert_asn1(cert=i.public_bytes(encoding=serialization.Encoding.DER))[0] for i in crypto_x509.load_pem_x509_certificates(data=ca_pem_strings)]

    for idx, i in enumerate(iterable=ca_certs, start=0):
        if not i.ca:
            logger.error("NO es CA: %s", ca_names[idx])
            logger.error("Solo se puede establecer confianza con certificados que sí sean Autoridad Certificadora.")
            exit()

    logger.info("Se procesaron las siguientes autoridades certificadoras:\n")
    for idx, i in enumerate(iterable=ca_names, start=1):
        print(f'  ({idx}) {i}')

    core_utils.continuar_salir(msj='\n¿Confía en estas CA y desea importarlas en el programa? (y/n): ')

    from efcli.xdg.xdg_config import STATE_FILE, DATA_PKI_DIR
    state = xdg_config.load_state_file()

    base_prefix = 20
    last_prefix = base_prefix
    if state['assets']['external_pki']:
        last_prefix = int(Path(state['assets']['external_pki'][-1]).name[:Path(state['assets']['external_pki'][-1]).name.index('-')])

    nueva_ca = f'{DATA_PKI_DIR}/{str(last_prefix + 1)}-{Path(cafile).stem}.pem'
    state['assets']['external_pki'].append(nueva_ca)
    nuevo_state = json.dumps(obj=state, indent=2, ensure_ascii=False)

    with open(STATE_FILE, 'w') as f:
        f.write(nuevo_state)
    with open(nueva_ca, 'wb') as f:
        f.write(ca_pem_strings)

    logger.info("CA importada correctamente!")
    return

@wrappers.salida_limpia()
@wrappers.requiere(fn_condicion=check_env, si_false="No cuenta con un entorno viable (use: 'efcli init').")
def del_ca():
    from efcli.xdg.xdg_config import STATE_FILE
    state = xdg_config.load_state_file()

    if not state['assets']['external_pki']:
        logger.error("No se tienen PKI externas importadas, no hay nada por borrar.")
        exit()

    logger.info("=== PKIs Externas ===")
    for idx, i in enumerate(iterable=state['assets']['external_pki'], start=1):
        logger.info("%s: %s", idx, Path(i).stem[Path(i).stem.index('-')+1:])

    print()
    while True:
        opcion = int(regex.input_regex(patron=regex.NUMERICO, mensaje="Ingrese el n° de la PKI que desea borrar: ", pista="Solo números naturales positivos."))
        if opcion == 0 or opcion > idx: # idx es lo mismo que len() sobre los usuarios
            logger.warning("No existe una PKI con ese número. Vuelva a ingresarlo.")
        else:
            seleccionado = Path(state['assets']['external_pki'][opcion - 1]) # -1 por el start en enumerate
            break

    print()
    logger.info("Ha seleccionado la PKI: '%s'", seleccionado.stem[seleccionado.stem.index('-')+1:])
    while True:
        confirmar = input('¿Desea borrarlo? (y/n): ')
        if confirmar == 'y':
            print('Borrando...')
            break
        elif confirmar == 'n':
            print('Saliendo...')
            exit()
        else:
            print('Ingrese una opción correcta.')

    del(state['assets']['external_pki'][opcion - 1])
    nuevo_state = json.dumps(obj=state, indent=2, ensure_ascii=False)

    with open(STATE_FILE, 'w') as f:
        f.write(nuevo_state)
    seleccionado.unlink()

    logger.info("PKI: '%s' borrada correctamente!", seleccionado.stem[seleccionado.stem.index('-')+1:])

import logging
from pathlib import Path
from cryptography.x509 import ocsp as crypto_ocsp

from . import fetcher, ocsp_utils

logger = logging.getLogger(__name__)

def imprimir_respuesta(resp_file: str):
    if not isinstance(resp_file, str):
        logger.error("Formato incorrecto de argumento ingresado. Saliendo...")
        return False
    if not Path(resp_file).exists():
        logger.error("El archivo inidicado no existe. Saliendo...")
        return False
    with open(resp_file, "rb") as f:
        resp_bytes = f.read()

    try:
        resp = crypto_ocsp.load_der_ocsp_response(data=resp_bytes)
    except Exception as e:
        logger.error("No es una respuesta OCSP (DER) (%s)", e)
        return False
    else:
        print(ocsp_utils.parse_response(der_bytes=resp_bytes)[1]) # se imprime independientemente del código de respuesta
    return True

def imprimir_estado(response: str | bytes):
    from colorama import Fore
    if isinstance(response, str):
        if not Path(response).exists():
            logger.error("El archivo inidicado no existe. Saliendo...")
            return False
        with open(response, "rb") as f:
            resp_bytes = f.read()
    elif isinstance(response, bytes):
            resp_bytes = response
    else:
        logger.error("Formato incorrecto de argumento ingresado. Saliendo...")
        return False

    try:
        resp = ocsp_utils.crypto_ocsp.load_der_ocsp_response(data=resp_bytes)
    except Exception as e:
        logger.error("No es una respuesta OCSP (DER) (%s)", e)
        return False
    else:
        logger.info("Parseando...")
        rp = ocsp_utils.parse_response(der_bytes=resp_bytes)
        if not rp[0]:
            logger.warning("Excepción del código de respuesta!")
            logger.warning("No es posible determinar la validez de certificado con este tipo de respuesta.")
            print(f"\n{rp[1]}\n")
            return False

        day = str(resp.produced_at_utc.day).rjust(2)
        fecha_respuesta = resp.this_update_utc.strftime(f'%H:%M:%S {day} %b %Y UTC')

        if resp.certificate_status == crypto_ocsp.OCSPCertStatus.GOOD:
            print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Certificado vigente.")
            print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Confirmado con fecha: {fecha_respuesta}")
        elif resp.certificate_status == crypto_ocsp.OCSPCertStatus.REVOKED:
            logger.warning("Certificado REVOCADO.")
            logger.warning("Revocado en fecha: %s", fecha_respuesta)
        elif resp.certificate_status == crypto_ocsp.OCSPCertStatus.UNKNOWN:
            logger.error("Estado del certificado DESCONOCIDO.")
        else:
            pass
    return True

def nueva_request(propia: bool = False, cert_file: str = None):
    import time
    from colorama import Fore

    from efcli.core import pki, x509, archivos
    from efcli.xdg import xdg_config, usuarios

    xdg_config.load_global()
    trust_roots       = xdg_config.GLOBAL_CONFIG['PKI']['trust_roots']
    intermediate_cas  = xdg_config.GLOBAL_CONFIG['PKI']['intermediate_cas']
    endpoints         = xdg_config.GLOBAL_CONFIG['OCSP']['endpoints']
    added_name = ''

    if propia:
        cert_file = usuarios.load_current_user_conf()['firmante']['certificado']
        added_name = '(USUARIO PRINCIPAL)'

    if not isinstance(cert_file, str):
        logger.error("Formato incorrecto de argumento ingresado. Saliendo...")
        return False
    if not Path(cert_file).exists():
        logger.error("El archivo inidicado no existe. Saliendo...")
        return False
    with open(cert_file, "rb") as f:
        cert_bytes = f.read()

    cert, encode = x509.cargar_cert_asn1(cert=cert_bytes)
    cn = x509.leer_campo_en_subject(subject=cert.subject, field="common_name")
    sujeto = x509.leer_subject_simple(cert=cert)
    pki_ctx = pki.get_validation_context(trust_roots=trust_roots, intermediate_cas=intermediate_cas)
    try:
        SUBJECT_CA_CHAIN = [i for i in pki.get_ca_chain(cert=cert, tipo="firmante", pki_ctx=pki_ctx)]
    except Exception:
        logger.error("No se puede establecer el contexto PKI del firmante.")
        print('Saliendo...')
        return False
    else:
        X509_ISSUER    = SUBJECT_CA_CHAIN[-2]
        X509_SUBJECT   = SUBJECT_CA_CHAIN[-1]

    request = ocsp_utils.coinstruir_OCSPRequest(cert_client=X509_SUBJECT, cert_issuer=X509_ISSUER)
    # Mientras la estrucutra de la cadena se mantenga constante la numeración dura del indice funciona.

    logger.info("Iniciando Petición OCSP.")
    logger.info("Certificado X.509: %s (%s) %s", sujeto, encode, added_name)
    for i in endpoints:
        logger.info("Consultando endpoint: '%s'", i)
        response = fetcher.fetch(ocsp_request=request, endpoint=i)
        if response:
            print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] El endpoint ha respondido.")
            break

    if not response:
        logger.error("No fue posible comunicarse con el endpoint OCSP, no se pudo determinar el estado del certificado.")
        return False

    raw_response   = response.dump()
    pr              = ocsp_utils.parse_response(der_bytes=raw_response)
    nombre          = f"{cn}.OCSP_RESPONSE.{int(time.time())}"
    archivo_binario = {nombre: response.dump()}
    archivo_plano   = {nombre: pr[1].encode('utf-8')} # se escribe bytes
    
    if pr[0] == True:
        imprimir_estado(response=raw_response)
    else:
        logger.warning("Excepción del código de respuesta!")
        logger.warning("El endopint respondió, pero NO con una respuesta estándar 'successful (0x0)'")
        print(f"\n{pr[1]}\n")

    archivos.guardar_archivos(".", "der", **archivo_binario)
    archivos.guardar_archivos(".", "txt", **archivo_plano)
    logger.info("Reviselo en los archivos.")
    logger.info("'%s.der'", nombre)
    logger.info("'%s.txt'", nombre)
    return True
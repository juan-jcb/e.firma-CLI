from asn1crypto import x509 as asn1_x509
from asn1crypto import ocsp as asn1_ocsp
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.hazmat.primitives.serialization import Encoding

def coinstruir_OCSPRequest(cert_client: asn1_x509.Certificate, cert_issuer: asn1_x509.Certificate) -> asn1_ocsp.OCSPRequest:
    req = asn1_ocsp.OCSPRequest({
        'tbs_request': {
            'request_list': [{
                'req_cert': {
                    'hash_algorithm': {'algorithm': 'sha1'},
                    'serial_number': cert_client.serial_number,
                    'issuer_name_hash': cert_issuer.sha1,
                    'issuer_key_hash': cert_issuer.public_key.sha1,
                }
            }]
        }
    })

    return req

def parse_response(der_bytes: bytes) -> tuple[bool, str]:
    """
    Parsea una respuesta OCSP en formato estándar de OpenSSL desde
    sus bytes en DER.

    :param der_bytes:
        bytes en DER de la respuesta OCSP (se asumen bytes de una
        respuesta estructuralmente parseable).

    :return:
        :class:`tuple` con 2 elementos.

        Indice 0: :class:`bool` de flag indicativo de si la respuesta
        parseada es válida, True para "successful (0x0)", False para
        cualquiera 0x1 - 0x6.

        Indice 1: :class:`str` de la respuesta parseada para imprimir
        o almacenar en variable.
    """

    status_map = {
        crypto_ocsp.OCSPResponseStatus.SUCCESSFUL: "successful (0x0)",
        crypto_ocsp.OCSPResponseStatus.MALFORMED_REQUEST: "malformedRequest (0x1)",
        crypto_ocsp.OCSPResponseStatus.INTERNAL_ERROR: "internalError (0x2)",
        crypto_ocsp.OCSPResponseStatus.TRY_LATER: "tryLater (0x3)",
        crypto_ocsp.OCSPResponseStatus.SIG_REQUIRED: "sigRequired (0x5)",
        crypto_ocsp.OCSPResponseStatus.UNAUTHORIZED: "unauthorized (0x6)",
    }
    resp = crypto_ocsp.load_der_ocsp_response(der_bytes)

    lines = []
    lines.append("OCSP Response Data:")
    lines.append(f"    OCSP Response Status: {status_map.get(resp.response_status, str(resp.response_status))}")

    # Se retorna tal cual cualquier respuesta que no sea útil junto a su flag False para evaluar fuera.
    if resp.response_status != crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return (False, "\n".join(lines))

    lines.append(f"    Response Type: Basic OCSP Response")
    lines.append(f"    Version: 1 (0x0)")
    responder_key = resp.responder_key_hash
    responder_name = resp.responder_name
    if responder_key:
        lines.append(f"    Responder Id: {responder_key.hex().upper()}")
    elif responder_name:
        lines.append(f"    Responder Id: {responder_name.rfc4514_string()}")

    if resp.produced_at_utc:
        day = str(resp.produced_at_utc.day).rjust(2)
        produced_at_utc = resp.produced_at_utc.strftime(f"%b {day} %H:%M:%S %Y UTC")
        lines.append(f"    Produced At: {produced_at_utc}")

    lines.append(f"    Responses:")
    lines.append(f"    Certificate ID:")

    hash_algo = resp.hash_algorithm.name.lower() if resp.hash_algorithm else "unknown"
    lines.append(f"      Hash Algorithm: {hash_algo}")
    lines.append(f"      Issuer Name Hash: {resp.issuer_name_hash.hex().upper()}")
    lines.append(f"      Issuer Key Hash:  {resp.issuer_key_hash.hex().upper()}")
    lines.append(f"      Serial Number: {format(resp.serial_number, 'X')}")

    cert_status_map = {
        crypto_ocsp.OCSPCertStatus.GOOD: "good",
        crypto_ocsp.OCSPCertStatus.REVOKED: "revoked",
        crypto_ocsp.OCSPCertStatus.UNKNOWN: "unknown",
    }
    lines.append(f"    Cert Status: {cert_status_map.get(resp.certificate_status, '?')}")

    if resp.certificate_status == crypto_ocsp.OCSPCertStatus.REVOKED:
        day = str(resp.revocation_time_utc.day).rjust(2)
        rev_time = resp.revocation_time_utc.strftime(f"%b {day} %H:%M:%S %Y UTC")
        lines.append(f"    Revocation Time: {rev_time}")
        if resp.revocation_reason:
            lines.append(f"    Revocation Reason: {resp.revocation_reason.value}")

    if resp.this_update_utc:
        day = str(resp.this_update_utc.day).rjust(2)
        lines.append(f"    This Update: {resp.this_update_utc.strftime(f'%b {day} %H:%M:%S %Y UTC')}")
    if resp.next_update_utc:
        day = str(resp.next_update_utc.day).rjust(2)
        lines.append(f"    Next Update: {resp.next_update_utc.strftime(f'%b {day} %H:%M:%S %Y UTC')}")

    sig_alg_name = resp.signature_hash_algorithm.name if resp.signature_hash_algorithm else "unknown"
    lines.append(f"    Signature Algorithm: {sig_alg_name}WithRSAEncryption")

    sig_hex = resp.signature.hex()
    sig_bytes = [sig_hex[i:i+2] for i in range(0, len(sig_hex), 2)]
    chunks = [":".join(sig_bytes[i:i+18]) for i in range(0, len(sig_bytes), 18)]
    lines.append(f"    Signature Value:")
    for chunk in chunks:
        lines.append(f"        {chunk}:")

    return (True, "\n".join(lines))

def extraer_x509_responder(der_bytes: bytes) -> asn1_x509.Certificate | None:
    """
    Retorna el `asn1crypto.x509.Certificate` incluido en una
    respuesta OCSP, o `None` en caso de no haberlo.
    """
    rsp = crypto_ocsp.load_der_ocsp_response(data=der_bytes)
    responder_certs = rsp.certificates
    if not responder_certs:
        return None

    responder_x509_bytes = responder_certs[0].public_bytes(encoding=Encoding.DER) # asumiendo que solo el indice 0 es el que se necesita
    crt = asn1_x509.Certificate.load(responder_x509_bytes)
    return crt

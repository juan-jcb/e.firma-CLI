"""
Estado del x509 del firmante mediante respuesta OCSP.
    
Para cada CMS, 1 entrada VRI. El DSS incluirá en /Certs el x509 del responder OCSP
y su cadena de confianza completa (sin raíz).

Para implementaciones de firma en lote, el patrón óptimo consiste en consultar el
OCSP una vez al inicio del proceso, verificar que nextUpdate sea posterior al tiempo
estimado de finalización del lote e incrustar esa misma respuesta en cada firma
generada. Si el proceso se extiende más de lo previsto y la respuesta expira,
se consulta nuevamente antes de continuar.

Como política interna de la aplicación, un techo práctico corto (2-5 minutos) es un
rango razonable para la mayoría de implementaciones de firma en lote.

Marco regulatorio como referencia superior. Si la normativa aplicable (eIDAS, una
política de firma nacional, el CPS del emisor del certificado) define criterios más
estrictos o más laxos, esos prevalecen sobre cualquier heurística propia.

El campo "Produced At" se convierte en el único ancla temporal disponible, por lo
que la ventana se mide desde ahí.
"""

import logging, requests, asyncio, aiohttp
from asn1crypto import ocsp as asn1_ocsp
from efcli.core.tls import get_ocsp_tls

logger = logging.getLogger(__name__)

# CAs primarily care about the "Content-Type: application/ocsp-request" header and a valid binary
# ASN.1 payload RFC 6960. Do not use standard browser-mimicking user agents (e.g., Chrome/Safari)
# for automated OCSP traffic, as some strict responders or firewalls may flag them.
OCSP_CLIENT_HEADERS = {
    "User-Agent": "OCSP-Client/1.0",
    "Content-Type": "application/ocsp-request",
}

def sync_fetch(ocsp_request: asn1_ocsp.OCSPRequest, endpoint: str) -> asn1_ocsp.OCSPResponse | None:
    """
    Función sincrona para hacer fetch manualmente de respuestas OCSP a los endpoints del SAT.
    Se hace POST manual por 2 razones dado el contexto de la PKI del SAT:

        1. Los certificados finales de usuario (FIEL/SELLO) NO incluyen extensión
           AIA y por ende tampoco una URL o URI para hacer peticiones OCSP o
           descargar CRLs y validar adecuadamente los certificados del firmante
           al momento de la firma, por lo que el flujo validación canónico de PKI
           no aplica para la PKI del Banxico y el SAT.

        2. El único endpoint OCSP públicamente accesible del SAT usa configs
           criptográficamente débiles (parametros DH de 1024 bits) por lo que
           incluso en clientes HTTP estándar resulta incomoda la comunicación
           con su servidor.

           requests.exceptions.SSLError:
           HTTPSConnectionPool(host='cfdi.sat.gob.mx', port=443): Max retries exceeded with url: /edofiel/
           (Caused by SSLError(SSLError(1, '[SSL: DH_KEY_TOO_SMALL] dh key too small (_ssl.c:1081)')))

    Esto no en sí un impedimento para hacer las peticiones y obtener respuestas
    útiles ya que afortunadamente su servidor HTTP soporta Diffie-Hellman de ECC,
    por lo que con 'requests' se declararán suites de cifrado que explicitamente
    usen ECDH en lugar de DH modular tradicional.
    """
    class TLSAdapter(requests.adapters.HTTPAdapter):
        def __init__(self, ssl_context=None, **kwargs):
            self.ssl_context = ssl_context
            super().__init__(**kwargs)

        def init_poolmanager(self, *args, **kwargs):
            kwargs['ssl_context'] = self.ssl_context
            return super().init_poolmanager(*args, **kwargs)

    TLS_OCSP_SAT = get_ocsp_tls()
    SESSION = requests.Session()
    SESSION.mount(prefix="https://", adapter=TLSAdapter(ssl_context=TLS_OCSP_SAT))

    try:
        response = SESSION.post(
            url=endpoint,
            headers=OCSP_CLIENT_HEADERS,
            data=ocsp_request.dump()
        )
        response.raise_for_status()
    except Exception as e:
        logger.warning("FALLO EN LA COMUNICACIÓN CON EL RESPONDER.")
        logger.warning("%s", e)
        return None
    else:
        try:
            rsp = asn1_ocsp.OCSPResponse.load(encoded_data=response.content)
        except Exception as e:
            print(f"Error al cargar 'OCSPResponse': {e}")
            return None
        else:
            return rsp

# TODO: en futura "firma multiple" lo adecuado sería usar esta función para obtener los estados OCSP.
async def async_fetch(ocsp_request: asn1_ocsp.OCSPRequest, endpoint: str):
    TLS_OCSP_SAT = get_ocsp_tls()
    conector = aiohttp.TCPConnector(ssl_context=TLS_OCSP_SAT, limit=100, ttl_dns_cache=300)

    async with aiohttp.ClientSession(connector=conector) as session:
        try:
            async with session.post(
                url=endpoint,
                headers=OCSP_CLIENT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=10),

                data=ocsp_request.dump(),
            ) as rsp:
                rsp.raise_for_status()
                raw_response = await rsp.read()

        except aiohttp.ClientResponseError as e:
            print(f"Error HTTP {e.status}: {e.message}")

        except asyncio.TimeoutError:
            print("La solicitud superó el tiempo límite")

        else:
            try:
                ocsp_rsp = asn1_ocsp.OCSPResponse.load(encoded_data=raw_response)
            except Exception as e:
                print(f"Error al cargar 'OCSPResponse': {e}")
                return None
            else:
                return ocsp_rsp

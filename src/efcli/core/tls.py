import ssl, aiohttp
from functools import cache
from typing import Iterator

from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.util import LazySession
#from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend

from efcli.config import TIMESTAMPING_CLIENT_HEADERS
from .regex import es_https

class SesionTlSPerezosa(LazySession):
    """
    Subclase variante de LazySession que retrasa la creación de la
    ClientSession real hasta la primera llamada a get_session(), pero
    construyéndola con un connector TLS y timeout propios en vez de
    la ClientSession() directa de la implementación base.

    no hay asyncio.Lock porque igual que en la implementación original
    de pyhanko, la línea self._session = aiohttp.ClientSession(...) es
    completamente síncrona (el constructor de ClientSession no hace await
    de nada), así que no hay punto de suspensión entre el chequeo is None
    y la asignación. Dos corrutinas que llamen a get_session() "casi
    simultáneamente" seguirán ejecutándose una a la vez dentro de ese
    bloque sin ceder el control al loop, por lo que no hay condición de
    carrera real en asyncio de un solo hilo.
    """

    def __init__(self, ssl_context: ssl.SSLContext, *, timeout: int = 10):
        super().__init__()          # deja self._session = None
        self._ssl_context = ssl_context
        self._timeout = timeout

    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=self._ssl_context),
                timeout=aiohttp.ClientTimeout(total=self._timeout),
            )
        return self._session

    @property
    def is_open(self) -> bool:
        return self._session is not None

    # close() se hereda tal cual de LazySession: opera sobre self._session
    # sin conocer connector ni ssl_context, así que no hace falta tocarlo.

class TransporteTLSFirmas:
    """
    Sesiones TLS asincronas 'lazy' con aiohttp.ClientSession para el bucle de firma.

    Permite instanciar AIOHttpTimeStamper de pyhanko sin necesidad de tener una sesión
    http asincrona ya abierta. Se instancia el transporte y solo si se necesita abrir
    sockets se inicia la aiohttp.ClientSession real. Si en algún momento de la sesión
    de firma se usa un "async_sign_pdf" o un "async_timestamp_pdf" o que llame a
    get_session() en ese momento se inicia la sesión real sin depender de un bloque
    async with.

    No obstante esto no se realiza con gestor de contexto por lo que se debe cerrar
    este objeto explicitamente al final de la lógica de quien la instancie.
    """

    def __init__(self, ssl_context: ssl.SSLContext, *, timeout: int = 10):
        self._sesion_perezosa = SesionTlSPerezosa(ssl_context, timeout=timeout)

    def get_timestamper(self, tsa_endpoint: str, *, https: bool = True) -> AIOHttpTimeStamper:
        """
        Crea un AIOHttpTimeStamper apuntando a `tsa_endpoint`, reutilizando
        la sesión/conexión TLS ya abierta. Se puede llamar varias veces
        (una por endpoint) sin coste adicional de conexión.
        """
        return AIOHttpTimeStamper(
            session=self._sesion_perezosa,          # AIOHttpTimeStamper.get_session()
            url=tsa_endpoint,                       # hará isinstance(..., LazySession)
            https=https,                            # y delegará en tu get_session()
            headers=TIMESTAMPING_CLIENT_HEADERS,
        )

    def iter_timestampers(self, tsa_endpoints: list[str]) -> Iterator[AIOHttpTimeStamper]:
        """
        Generador que hace yield de un AIOHttpTimeStamper por cada endpoint
        de `tsa_endpoints`, en orden, reutilizando siempre la misma sesión.

        Pensado para lógica de fallback: se pide el primer valor antes de
        empezar a firmar, y si ocurre una excepción de comunicación con la
        TSA dentro del bloque de firma, se llama a `next()` sobre este mismo
        generador para obtener el timestamper del siguiente endpoint sin
        perder la conexión TLS.

        Lanza StopIteration cuando se agotan los endpoints configurados.
        """
        for endpoint in tsa_endpoints:
            yield self.get_timestamper(
                tsa_endpoint=endpoint,
                https=es_https(url=endpoint)
            )

    async def cerrar(self):
        await self._sesion_perezosa.close()  # idempotente si nunca se abrió

"""
Funciones basadas en politicas de uso de TLS definidas por *intención*.
Por ejemplo.

    - Los endpoints OCSP del SAT requieren suites de cifrado especificas.
    - Los endpoints TSA de PSC requieren libertad de configuración en confianza
      puesto que podrían o no venir de una PKI privada no preconfigurada.

"""

@cache
def make_tls_trust(trust_system_store: bool = True, ca_bundle: str = None,) -> ssl.SSLContext:
    """
    Carga un contexto SSL basado en confianza: Solo sistema, Solo CA privada, Sistema + CA privada.

    Formas de combinar:

        trust_system_store  ca_bundle     Resultado
        True                None          Solo el almacén del sistema (o certifi, según plataforma)
        False               ruta          Solo CA privada, nada más es válido ni siquiera sistema
        True                ruta          Combinado Sistema y CA privada.

    """

    if trust_system_store:
        ctx = ssl.create_default_context() # "truststore.SSLContext(...)" también aplicaría
        if ca_bundle:
            ctx.load_verify_locations(cafile=ca_bundle)
    
    else:
        if not ca_bundle:
            raise ValueError("Necesita un 'ca_bundle' si usa 'trust_system_store=False'")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=ca_bundle)

    return ctx

@cache
def get_ocsp_tls() -> ssl.SSLContext:
    """
    Carga el contexto TLS necesario para utilizar los endpoints OCSP del SAT.

    Especificamente para: 'https://cfdi.sat.gob.mx/edofiel' que requiere suites
    de cifrado especificas sin Diffie-Hellman modular.

    Se usará TLS 1.2 en vez de 1.3 por libertad de modificación manual de suites
    y compatibilidad general (lo más prudente es asumir que los endpoints no
    soportan 1.3 y evitarse dolores de cabeza :p).
    """

    ctx = ssl.create_default_context()
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "!aNULL:" # no 'anonymous Diffie-Hellman'
        "!eNULL:" # no 'NULL encryption'
        "!RC4:"
        "!3DES"
        "!MD5"

        # Suites para DH modular 'FFDHE' para servers sin soporte ECDH. Primero RSA luego DSA (descomentar solo si acaso)
        #"DHE-RSA-AES256-GCM-SHA384:"
        #"DHE-RSA-AES128-GCM-SHA256:"
        #"DHE-DSS-AES256-GCM-SHA384:"
        #"DHE-DSS-AES128-GCM-SHA256:"
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION

    return ctx

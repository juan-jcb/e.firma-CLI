import ssl, aiohttp
from functools import cache

from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend

from efcli.config import TIMESTAMPING_CLIENT_HEADERS

class TransporteTLSFirmas:
    """
    Gestor de contexto: Conector async de aiohttp para gestionar el transporte
    TLS de las conexiónes que se realizan en los bucles de firma:
    
        1. fetchers async propios para OCSP en perfiles L
        2. timestampers de pyhanko en perfiles T, A
    
    Se reutiliza la misma conexión TLS durante toda la sesión de firma, se
    abre al entrar al contexto y se cierra al salir.

    Se necesita un gestor de contexto para las conexiones salientes de las
    firmas ya que firmamos en bucle, y no queremos bombardear innecesariamente
    los endpoints de las TSAs ni OCSPs con handshakes TCP + TLS completos por
    cada iteración y nos comamos un rate-limiting o directamente nos bloquee
    cualquier firewall intermedio.
    
    Lo más adecuado es evitar usar las funciones sincronas de pyhanko, que
    crean conexiones completas en cada iteración. Gestionaremos nuesto propio
    bucle de eventos, nuesto propio conector http y usaremos directamente el
    codigo (que ya es) asincrono de pyhanko.

    Así mismo.

    Dado que el uso de TSA es considerablemente más voluminoso, más propenso
    a errores en comparación con el manejo de los responders OCSP; se definirá
    en esta misma clase un método de instanciación de timestampers para usarse
    adentro del contexto:
    
        `get_timestamper()`
    
    Esto nos permite implementar lógica de fallback entre endpoints de TSA de
    manera mucho más simple, sin reabrir la conexión ni reformular el flujo
    de firma general en el bucle.
    """

    def __init__(self, ssl_context: ssl.SSLContext, *, timeout: int = 10):
        self._ssl_context = ssl_context
        self._timeout = timeout
        self._session: aiohttp.ClientSession | None = None
        self._fetcher_backend: AIOHttpFetcherBackend | None = None
        self._fetchers = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=self._ssl_context)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self._timeout),
        )
        self._fetcher_backend = AIOHttpFetcherBackend(session=self._session)
        self._fetchers = await self._fetcher_backend.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._fetcher_backend is not None:
            await self._fetcher_backend.__aexit__(exc_type, exc, tb)
        if self._session is not None:
            await self._session.close()

    @property
    def fetchers(self):
        return self._fetchers

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("TsaTransport no está abierto (usa 'async with').")
        return self._session

    def get_timestamper(self, tsa_endpoint: str, *, https: bool = True) -> AIOHttpTimeStamper:
        """
        Crea un AIOHttpTimeStamper apuntando a `tsa_endpoint`, reutilizando
        la sesión/conexión TLS ya abierta. Se puede llamar varias veces
        (una por endpoint) sin coste adicional de conexión.
        """
        return AIOHttpTimeStamper(url=tsa_endpoint, session=self.session, https=https, headers=TIMESTAMPING_CLIENT_HEADERS)

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

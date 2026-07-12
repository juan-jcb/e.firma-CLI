import logging, getpass, asyncio
from io import BytesIO
from pathlib import Path
from time import perf_counter, sleep, time
from datetime import datetime, timezone
from colorama import Fore

from asn1crypto import pem
from pyhanko.sign import signers, fields, timestamps
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

from pyhanko.sign.timestamps.common_utils import TimestampRequestError

from efcli import config
from efcli.core import core_utils, cripto, wrappers, registros, pki, x509, tls
from efcli.xdg import xdg_config, usuarios
from efcli.ocsp import fetchers, ocsp_utils
from efcli.pdf import pdf_utils
from efcli.firma import prefirma

logger = logging.getLogger(__name__)

xdg_config.load_global()
BANXICO_PKI_CTX = pki.get_validation_context(
    trust_roots=xdg_config.GLOBAL_CONFIG['PKI']['trust_roots'],
    intermediate_cas=xdg_config.GLOBAL_CONFIG['PKI']['intermediate_cas'],
)
TSA = xdg_config.GLOBAL_CONFIG['TSA']
OCSP = xdg_config.GLOBAL_CONFIG['OCSP']
PDF_RUTA_BASE = xdg_config.GLOBAL_CONFIG['pdf_ruta_base']

async def manejador_ocsp(firmante_crt, firmante_issuer_crt, dir_save):
    OCSP_INFO = None
    OCSP_REQUEST = ocsp_utils.coinstruir_OCSPRequest(cert_client=firmante_crt, cert_issuer=firmante_issuer_crt)
    OCSP_RESPONSE = None
    OCSP_RAW_RESPONSE = None
    OCSP_PARSED_RESPONSE = None
    OCSP_RESPONDER_X509 = None
    OCSP_CA_CHAIN = None

    OCSP_RESPONSES = None
    OCSP_X509_DSS = []
    PERFIL_OCSP = []

    # iteración sobre todos los endpoints disponibles para hacer la petición.
    for endpoint in OCSP['endpoints']:
        logger.info("Consultando endpoint: %s", endpoint)
        OCSP_RESPONSE = fetchers.sync_fetch(ocsp_request=OCSP_REQUEST, endpoint=endpoint)
        if not OCSP_RESPONSE:
            print()
            continue

        logger.info("Respuesta obtenida.")
        OCSP_RAW_RESPONSE = OCSP_RESPONSE.dump()
        es_good, OCSP_PARSED_RESPONSE = ocsp_utils.parse_response(der_bytes=OCSP_RAW_RESPONSE)

        # cert status good, lo que realmente nos interesa, sale directamente.
        if es_good:
            hora = int(time())
            estado = OCSP_RESPONSE['response_bytes']['response'].parsed['tbs_response_data']['responses'][0]['cert_status']
            break

        # Sí hay respuesta, pero no es operativamente útil (cualquiera entre 0x1-0x6).
        logger.warning("Excepción en el código de respuesta!")
        logger.warning("El endpoint OCSP respondíó, pero NO con material útil para usar como respuesta OCSP para una firma funcional.")
        print(f"\n{OCSP_PARSED_RESPONSE}\n")
        logger.error("No es posible continuar en éste estado y preservar el perfil de firma 'L'.")
        logger.error("Tiene 2 opciones:")
        logger.error("  1. Continuar firma pero SIN validación OCSP externa; el perfil de firma se mantendrá en 'Basic (B)'.")
        logger.error("  2. Cancelar el proceso, esperar a que se regularice el estado del responder y volver a intentar.")
        core_utils.continuar_salir(msj='\n¿Continuar con el proceso de firma? (y/n): ')

    # post iteración de endpoints

    # 0. se recorrieron todos los endpoints y salió naturalemnte del bucle sin haberse obtenido respuesta.
    if not OCSP_RESPONSE:
        logger.error("Han fallado todos los servidores OCSP. Esto AFECTA DIRECTAMENTE al perfil de validación 'Long-Term (L)'.")
        logger.error("Tiene 2 opciones:")
        logger.error("  1. Continuar firma pero SIN validación OCSP externa; el perfil de firma se mantendrá en 'Basic (B)'.")
        logger.error("  2. Cancelar el proceso, esperar un par de minutos a que se regularice el estado del responder y volver a intentar.")
        core_utils.continuar_salir(msj='\n¿Continuar con el proceso de firma? (y/n): ') # sale del if, elif, elif, else y cae en el bucle de firmado.

    # 1. hay respuesta, con status good
    elif (OCSP_RESPONSE and estado.name == "good"):
        logger.info("Certificado X.509 válido en PKI (Cert Status: %s).", estado.name)
        OCSP_RESPONSES = [OCSP_RESPONSE] # /OCSPs de /DSS recibe una "lista de objetos respuesta" (no objetos respuesta solos).

        # Recuperación del certificado x509 del responder desde su respuesta para su inclusión en /Certs de /DSS.
        logger.info("(Si existiese) Recuperando x509 del responder...")
        OCSP_RESPONDER_X509 = ocsp_utils.extraer_x509_responder(der_bytes=OCSP_RAW_RESPONSE)

        # la práctica correcta es incluir el x509 del responder en /Certs de /DSS, independientemente de si su
        # certificado ya está incluído en su respuesta OCSP (y por ende en lo que será /OCSPs). La duplicidad de
        # datos no viola ninguna norma y garantiza que el documento sea validable sin conexión ahora y en el
        # futuro. A grandes razgos se entiende lo siguiente:
        #
        #   /DSS
        #   ├── /Certs
        #   │   ├── Certificado del firmante
        #   │   ├── N cantidad CAs intermedias
        #   │   ├── CA raíz (tecnicamente posible pero no recomendado: la raíz se asume en el validador)
        #   │   └── Certificado del OCSP Responder (si existe incluír siempre, aunque ya esté en la respuesta OCSP)
        #   │
        #   ├── /OCSPs
        #   │   └── BasicOCSPResponse (puede o no contener el x509 del responder)
        #   │
        #   └── /CRLs
        #       └── (si aplicase)
        #
        # - Una firma PAdES-LT/LTA exige que la cadena de validación sea autocontenida. El validador no debe
        #   necesitar conexión a internet para reconstruirla.
        # - El estándar ETSI EN 319 102-1 §5.5 indica que todos los certificados necesarios para validar los
        #   materiales de revocación deben estar presentes en /Certs.
        # - Los validadores (DSS de la Comisión Europea) buscan certificados en /Certs directamente y no todos
        #   implementan extracción desde la respuesta OCSP.
        #
        #   Respuesta OCSP en /OCSPs
        #   └── BasicOCSPResponse
        #       └── certs[]   ← certificado del responder (opcional según RFC 6960)
        #
        #   /Certs            ← debe incluirse el x509 del responder aquí.
        #
        # Referencias normativas.
        #
        #   RFC 6960 – Online Certificate Status Protocol (OCSP)
        #   ETSI EN 319 102-1 – Procedures for Creation and Validation of AdES Digital Signatures
        #   ETSI EN 319 122-1 – CAdES (la base de PAdES)
        #   ISO 32000-2 – PDF 2.0, estructura del diccionario DSS

        if OCSP_RESPONDER_X509:
            OCSP_INFO = True
            logger.info('Responder incluyó su x509 en la respuesta: "%s" ', x509.leer_subject_simple(cert=OCSP_RESPONDER_X509))
            logger.info("Se adjuntará el certificado del responder como contexto en /Certs de /DSS).")
            OCSP_X509_DSS.append(OCSP_RESPONDER_X509)

            # Si existe x509 del responder se buscará construír su cadena completa en este contexto PKI y se añadirán
            # los certificados de sus CAs intermedias (según aplique) en /Certs de /DSS en el orden antes propuesto:
            # responder, issuer, issuer, ... (sin raíz)
            logger.info("Reconstruyendo cadena de confianza del responder...")
            try:
                OCSP_CA_CHAIN = [i for i in await pki.async_get_ca_chain(cert=OCSP_RESPONDER_X509, tipo='ocsp_responder', pki_ctx=BANXICO_PKI_CTX)]
                #ocsp_root_x509      = OCSP_CA_CHAIN[0]
                #ocsp_inters_x509    = OCSP_CA_CHAIN[-3:0:-1]
                ocsp_issuer_x509    = OCSP_CA_CHAIN[-2]
                #ocsp_responder_x509 = OCSP_CA_CHAIN[-1]

                # TODO: Aquí no es ncesario desglosar con 'if OCSP_INTERS:' ???

            except Exception as e:
                logger.warning("No se pudo cargar la cadena de certificados del responder. Continuando sin ellos... (%s)", e)
            else:
                logger.info("Cadena del responder OCSP cargada.")
                # Una vez con la cadena completa del responder se debe evaluar si existe duplicado de Isusers (que el
                # issuer del responder sea el mismo del firmante) dado que es la topología esperada en la mayoría de
                # casos, y afortunadamente banxico sí lo hace de forma estándar y define los x509 de responder y los
                # FIEL/SELLO al mismo nivel jerarquico en su PKI (ambos como end-entities).
                #
                # En caso de ser mismo issuer se añadirá solo 1 x509 a /CERTS:      [end, end_issuer, ocsp]
                # Si son issuers diferentes se añade N cantidad en orden normal:    [end, end_issuer, ocsp, ocsp_issuer, ...]

                if ocsp_issuer_x509.dump() == firmante_issuer_crt.dump():
                    logger.info("Firmante y responder comparten MISMO Issuer.")
                    logger.info("Se mantendrá 1 solo x509 de issuer en /Certs de /DSS (valída para ambos firmante y responder).")
                else:
                    logger.warning("Firmante y responder tienen DISTINTO Issuer.")
                    logger.info("Se incluirán los x509 de cada issuer en /Certs de /DSS.")
                    OCSP_X509_DSS.append(ocsp_issuer_x509)

                    # TODO:
                    # Solo se está incluyendo el issuer del responder pero no un factible "N cantidad de intermedias"

                PERFIL_OCSP.append('L')
                logger.info("Perfil 'Long-Term (L)' completo (validación externa).")

        else:
            logger.warning("NO hay certificados x509 incluidos en la respuesta del responder. Continuado sin el...")

    # 2. hay respuesta, con status revoked
    elif (OCSP_RESPONSE and estado.name == "revoked"):
        # con certs expirados el responder del SAT marca "revoked" e incluye fecha revocación.
        print()
        logger.error("Certificado X.509 REVOCADO.")
        logger.error("Revocado desde: %s (UTC)", estado.chosen['revocation_time'].native.strftime("%Y-%m-%dT%H:%M:%SZ"))
        logger.error("(opcional) Razón: %s", estado.chosen['revocation_reason'].native)
        logger.error("DEBE regularizar su estado con su CA emisora.")
        print()
        logger.warning("ATENCIÓN!, es técnicamente posible continuar con la firma pero bajo su propio criterio.")
        logger.warning("Tiene 2 opciones:")
        logger.warning("  1. Firmar en estado revocado, lo cual SERÁ VISIBLE en todas sus firmas, y se mantendrá el perfil en 'Basic (B)'.")
        logger.warning("  2. Cancelar el proceso e intentar firmar nuevamente una vez haya regularizado su situación con su CA emisora.")
        core_utils.continuar_salir(msj='\n¿Continuar con el proceso de firma? (y/n): ')

        # TODO:
        # Bajo el flujo normal de uso de efcli, se entra a este bloque unicamente cuando el certificado
        # del firmante ha sido revocado en su PKI, no cuando el certificado está expirado directamente
        # por fecha por la validación que hace pyhanko para construir las cadenas de validación exceptua.
        # certificados expirados por fecha.
        # ¿Debería ignorar la restricción (hecha en local) de expiración de certificado al construir su
        # cadena de validación para que deliberadamente se puedan enviar peticiones ocsp de certificados
        # ya expirados y en ambos resultados (revocado y expirado) y se unifiquen los flujos aquí?. No es
        # técnicamente necesario, pero podría hacerse.

    # 3. hay respuesta, con status unknown. TODO: desarrollar
    else:
        pass

    if OCSP_INFO:
        core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'der', status_ocsp=OCSP_RAW_RESPONSE)
        core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'txt', status_ocsp_textual=OCSP_PARSED_RESPONSE.encode('utf-8'))
        core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'pem', responder_x509=pem.armor(der_bytes=OCSP_RESPONDER_X509.dump(), type_name="CERTIFICATE"))
        if OCSP_CA_CHAIN:
            core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'pem', responder_cadena=pki.hacer_cadena_pem(chain_path=OCSP_CA_CHAIN, elementos="no_subject"))
            core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'txt', resumen_cadena=pki.leer_ca_chain_simple(chain_path=OCSP_CA_CHAIN).encode('utf-8'))

    return (PERFIL_OCSP, OCSP_RESPONSES, OCSP_X509_DSS)

def contexto(firmante_input: dict) -> dict | None:
    firmante_fiel = firmante_input['firmante']
    sig_meta = firmante_input['metadatos_firma']
    campo_visual = firmante_input['firma_visible']

    logger.info("Definiendo al firmante.")
    print("    1. Cargando contexto PKI del firmante...")

    cert, cert_encode = x509.cargar_cert_asn1(cert=firmante_fiel['certificado'])
    print(f"     • Certificado ({cert_encode}) cargado.")

    try:
        # En caso de que metan una CA intermedia nueva no se afecta este código (supuestamente ;-;)
        # dejando como unica acción necesaria la adición explicita del x509 nuevo en docs de PKI.
        firmante_ca_chain = [i for i in pki.get_ca_chain(cert=cert, tipo='firmante', pki_ctx=BANXICO_PKI_CTX)]

        #firmante_x509_root  = firmante_ca_chain[0]       # aunque se tiene acceso a su x509, la raíz se asume en el validador.
        firmante_inters_ca   = firmante_ca_chain[-3:0:-1] # slice invertido para incluir (desde -3) n cantidad de CAs intermedias sin raíz
        firmante_issuer      = firmante_ca_chain[-2]
        firmante_x509        = firmante_ca_chain[-1]

        # 'subject_certificates' es ambos "Certificates" en CMS y la base de /Certs en /DSS
        subject_certificates = [firmante_x509, firmante_issuer]
        if firmante_inters_ca:
            subject_certificates += [i for i in firmante_inters_ca]
            # si agregasen más CAs se distribuirán dinámicamente aquí. Por el momento 'firmante_inters_ca' será lista vacia
            # hasta que exista un elemento nuevo en indices de CAs intermedias, si no hay, se sumara por lógica de append de lista vacia.

    except Exception:
        logger.error("No se puede establecer el contexto PKI del firmante.")
        print('Saliendo...')
        return False
    else:
        print("     • Cadena de confianza establecida.")

    print("\n    2. Cargando clave privada del firmante...")
    res, tipo_pkey = cripto.es_pkey_cifrada(ruta_pkey=firmante_fiel['clave_privada'])
    if res == True:
        print("     • Clave privada cifrada.")
        while True:
            pkey_passwd = getpass.getpass(prompt="     • Contraseña: ", echo_char="*").encode('utf-8')
            if cripto.es_passwd_de_pkey(ruta_pkey=firmante_fiel['clave_privada'], tipo_encode=tipo_pkey, passwd=pkey_passwd):
                print(f"     • Clave privada ({tipo_pkey}) cargada.")
                break
            else:
                print("     • Contraseña INCORRECTA, vuelva a ingresarla.")
    else:
        print(f"     • Clave privada ({tipo_pkey}) NO está cifrada y no requiere contraseña.")
        print(f"     • Clave privada ({tipo_pkey}) cargada.")
        pkey_passwd = None
    print()

    try:
        firmante_simple = signers.SimpleSigner.load(
            key_file=firmante_fiel['clave_privada'],
            key_passphrase=pkey_passwd,
            cert_file=firmante_fiel['certificado'],

            other_certs=subject_certificates, # campo "Certificates" en el CMS. Mientras el orden aquí sea CONSTANTE, /Certs de /DSS será congruente.
                                              # [X509_SUBJECT, X509_ISSUER]

            # TODO:
            # sería ideal cargar el objeto certificado en cert_file en lugar de la ruta
            # de archivo en cert_file, pero de momento no provoca error
        )

    except Exception as e:
        logger.error("No se pudo instanciar al firmante. (%s)", e)
        return False

    print("    3. Cargando metadatos de la firma...")
    try:
        firmante_simple_sigmeta = signers.PdfSignatureMetadata(
            field_name=sig_meta['nombre_firma'],

            name=sig_meta['nombre_firmante'],
            reason=sig_meta['razon'],
            location=sig_meta['lugar'],
            contact_info=sig_meta['contacto'],
            md_algorithm=TSA['HASH'],
            timestamp_field_name=datetime.now(),

            subfilter=fields.SigSeedSubFilter.PADES,                    # Subfiltro estándar: /SubFilter /ETSI.CAdES.detached
            #subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,    # Subfiltro legacy:   /SubFilter /adbe.pkcs7.detached

            #use_pades_lta=False,
            #embed_validation_info=False,
            #validation_context=ValidationContext(),
            #signer_key_usage={'digital_signature', 'non_repudiation', 'data_encipherment', 'key_agreement'},
        )
    except Exception as e:
        logger.error("Error definiendo los meadatos de la firma, no puede firmarse en este estado. (%s)", e)
        return False
    else:
        print(f"     • ID Firma:      {sig_meta['nombre_firma']}")
        print(f"     • Nombre:        {sig_meta['nombre_firmante']}")
        print(f"     • Razón:         {sig_meta['razon']}")
        print(f"     • Lugar:         {sig_meta['lugar']}")
        print(f"     • Contacto:      {sig_meta['contacto']}")

    # Campo de firma visual en PDF
    if campo_visual['usar'] == True:
        #coords_x = 50
        #coords_y = 50
        ancho = 200
        alto = 50

        try:
            campo_visual = fields.SigFieldSpec(
                sig_field_name=sig_meta['nombre_firma'],
                on_page=campo_visual['pagina'],

                box=(
                    campo_visual['coords_x'],
                    campo_visual['coords_y'],
                    campo_visual['coords_x'] + ancho,
                    campo_visual['coords_y'] + alto,
                )
            )
        except Exception as e:
            logger.error("Fallo al configurar el CAMPO visible de la firma. (%s)", e)
            return False
        else:
            print("     • Campo visual:  xXxXxX TERMINAAAAAR")
    else:
        print('     • Campo visual:  NO se utilizará CAMPO para firma visible en PDF.')
        campo_visual = None

    return {
        "firmante_simple": firmante_simple,
        "firmante_simple_sigmeta": firmante_simple_sigmeta,
        "campo_visual": campo_visual,
        #"firmante_simple_ts_cms": firmante_simple_ts_cms, # El timestamper se omite deliberadamente para contexto()

        "subject_certificates": subject_certificates,
        "firmante_ca_chain": firmante_ca_chain,
        "preferencias_firma": firmante_input['perfiles_firma']
    }

async def firma(firmante_ctx: dict, pdfs: list) -> None:
    """
    Firmar digitalmente uno/muchos PDF. Firmante Individual.
    """    
    PDFs = pdfs
    l_pdfs = len(PDFs)
    ocsp_responses = None
    timer_ocsp = False
    tst_cms = None
    tst_dss = None
    dir_sesion_firma = Path(f'{PDF_RUTA_BASE}/({usuarios.load_state_users()['principal']}) Sesión de Firma - {datetime.now().strftime("%a %b %d %I:%M:%S %p %Y")}')
    perfil_firma_propuesto = ['B']
    perfil_firma_final = ['B']

    # /Certs de /DSS
    # El llenado de objetos certificado de la lista DSS_CERTS se prefiere en órden: [end, inter, inter, ...] SIN RAÍZ
    # para estár en conformidad con "ETSI EN 319 102-1 y 319 122-1 PAdES"
    # - Se empieza a llenar por el certificado del firmante y hasta N cantidad de sus CAs intermedias desde su
    #   atributo cert_registry.
    # - Posteriormente en caso de utilizar validación OCSP e incluir certificados x509 del responder, el orden
    #   de llenado continua en lógica de .append(): [end, inter, inter, ..., ocsp, inter, inter, ...] de igual
    #   forma sin incluír la raíz de ninguna entidad final ya que se asume esta existirá en el validador.
    dss_certs = firmante_ctx["subject_certificates"]

    tls_ctx = tls.make_tls_trust(trust_system_store=True, ca_bundle=None)
    async with tls.TransporteTLSFirmas(ssl_context=tls_ctx) as tls_transport:

        print()
        logger.info("Cargando contexto opcional de la firma...")

        # OCSP para estado del firmante (perfil 'L')
        if firmante_ctx['preferencias_firma']['OCSP'] == True:
            print(f"     • Se utilizará OCSP '{OCSP['endpoints'][0]}' para validación externa (Fallbacks: {len(OCSP['endpoints']) - 1}).")
            perfil_firma_propuesto[0] = 'L'
        else:
            print('     • NO se utilizará OCSP para validar su certificado X.509.')

        # TST en CMS (perfil 'T')
        if firmante_ctx['preferencias_firma']['TST_CMS'] == True:
            try:
                ts_cms = tls_transport.get_timestamper(tsa_endpoint=TSA['endpoints'][0], https=False)
            except Exception as e:
                logger.warning("No se pudo configurar timestamp para CMS. Continuando sin el...")
                print(e)
                ts_cms = None
            else:
                print(f"     • Se utilizará TSA '{TSA['endpoints'][0]}' para timestamping en su firma (CMS).")
                perfil_firma_propuesto.append('T')
        else:
            print('     • NO se utilizará TSA para timestamping en su firma (CMS).')
            ts_cms = None

        # TST en DSS /DocTimeStamp (perfil 'A'):
        if firmante_ctx['preferencias_firma']['TST_DSS'] == True:
            try:
                ts_dss = signers.PdfTimeStamper(timestamper=tls_transport.get_timestamper(tsa_endpoint=TSA['endpoints'][0]))
            except Exception:
                logger.warning("No se pudo configurar timestamp en PDF (/DocTimeStamp). Continuando sin el...")
                ts_dss = None
            else:
                print(f"     • Se utilizará TSA '{TSA['endpoints'][0]}' para timestamping en PDF (/DocTimeStamp).")
                perfil_firma_propuesto.append('A')
        else:
            print('     • NO se utilizará TSA para timestamping en PDF (/DocTimeStamp).')
            ts_dss = None

        # Instanciación de objeto "firmante de pdf" en la clase encapsuladora PdfSigner con las opciones acumuladas.
        try:
            FIRMANTE = signers.PdfSigner(
                signer=firmante_ctx['firmante_simple'],
                signature_meta=firmante_ctx['firmante_simple_sigmeta'],
                timestamper=ts_cms,
                new_field_spec=firmante_ctx['campo_visual'],
            )
        except Exception as e:
            print(e)
            exit()

        # Mensajes últimos de desglose y prompt de confirmación.
        print(f"\n[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Contexto operacional listo.\n")
        logger.info("Firmante: %s", x509.leer_subject_simple(cert=FIRMANTE.signer.signing_cert))
        logger.info("Perfil de firma propuesto: PAdES-B-%s", ''.join(perfil_firma_propuesto))
        #print(f'\n• Documentos a firmar: {PDFs}')
        #print(pki.leer_ca_chain_simple(chain_path=CA_CHAIN_SUBJECT))
        if firmante_ctx['preferencias_firma']['OCSP'] == True:
            print(f"\n{config.MENSAJES_MISC['msj_desfase_temporal']}")

        core_utils.continuar_salir(msj='\n¿Proceder y firmar? (y/n): ')

        # Lógica de sesión de firma.
        print()
        logger.info("Iniciando sesión de firma.")

        dir_sesion_firma.mkdir(parents=True)
        core_utils.guardar_archivos(f'{dir_sesion_firma}/firmante_info', 'txt', resumen_cadena=pki.leer_ca_chain_simple(chain_path=firmante_ctx['firmante_ca_chain']).encode('utf-8'))
        core_utils.guardar_archivos(
            f'{dir_sesion_firma}/firmante_info', 'pem',
            firmante_x509=pem.armor(der_bytes=FIRMANTE.signer.signing_cert.dump(), type_name="CERTIFICATE"),
            firmante_cadena=pki.hacer_cadena_pem(chain_path=firmante_ctx['firmante_ca_chain'], elementos="no_subject")
        )
        ini_time = perf_counter()
    
        with registros.modded_logs(target_logger=logger, fmt="[%(levelname)s] (%(asctime)s) %(message)s"):
            if firmante_ctx['preferencias_firma']['OCSP'] == True:
                print()
                logger.info("Iniciando validación externa mediante 'Online Certificate Status Protocol (OCSP)'.")
                perfil_ocsp, ocsp_responses, ocsp_x509_dss = await manejador_ocsp(
                    firmante_crt=dss_certs[0],
                    firmante_issuer_crt=dss_certs[1],
                    dir_save=dir_sesion_firma
                )
                if ocsp_x509_dss:
                    dss_certs += ocsp_x509_dss # [end, inter, inter, ..., ocsp, inter, inter, ...]
                if perfil_ocsp:
                    perfil_firma_final[0] = perfil_ocsp[0]

                # Por más pocho que sea el hardware 150 firmas en perfil alto no sobrepasan los 5 minutos, sería a partir
                # de 150 pdfs a firmar que empezariamos a usar la comparación por tiempo en cada iteración de firma para
                # evaluar si el tiempo transcurrido bajo perfil L sobrepasa 295 segundos (casi 5min) y así realizar una
                # nueva petición OCSP y continuar firmando bajo la misma lógica ordenada.
                if l_pdfs > 150:
                    timer_ocsp = True
                    techo_ocsp = 295
                    ocsp_time = perf_counter()

            # Bucle de firma sobre los PDFs.
            for idx, i in enumerate(iterable=PDFs, start=1): # tuplas de 3 elementos: ("Path del PDF", "bool de cifrado", "int de siguiente firma disponible").
                if timer_ocsp:
                    # si se firman menos de 150 pdfs: if false, no baja rendimiento.
                    # si se firman más de 150 pdfs: if true, se compara tiempo en cada iteración para gestionar a mano el nextUpdate.
                    if (perf_counter() - ocsp_time) > techo_ocsp:
                        perfil_firma_final = ['B']
                        print()
                        logger.warning("ATENCIÓN!, Se ha sobrepasado el techo práctico de tiempo para seguir usando la misma respuesta OCSP.")
                        logger.warning("Se realizará una NUEVA petición OCSP a los endpoints por defecto para corroborar nuevamente el estado del firmante.\n")
                        sleep(3)

                        logger.info("Iniciando nuevamente validación externa mediante 'Online Certificate Status Protocol (OCSP)'.")
                        perfil_ocsp, ocsp_responses, ocsp_x509_dss = await manejador_ocsp(
                            firmante_crt=dss_certs[0],
                            firmante_issuer_crt=dss_certs[1],
                            dir_save=dir_sesion_firma
                        )
                        if ocsp_x509_dss: # volvemos a llenar dss_certs con los x509 base de firmante + los del responder (si los hay)
                            dss_certs = firmante_ctx["subject_certificates"] + ocsp_x509_dss
                        else:
                            dss_certs = firmante_ctx["subject_certificates"]
                        if perfil_ocsp:
                            perfil_firma_final[0] = perfil_ocsp[0]
                            techo_ocsp += 298
                        else:
                            timer_ocsp = False
                        print()

                pdf = i[0]
                es_pdf_cifrado = i[1]

                # Manejo diferenciado entre indice de lista e indice mostrado en terminal
                nextsig_interno = i[2]
                nextsig_visual = i[2] + 1
                if nextsig_interno == 0:
                    firmas_previas = 0
                else:
                    firmas_previas = nextsig_visual - 1

                nombre_pdf_firmado = f"{dir_sesion_firma}/{pdf.stem}_FIRMADO{pdf.suffix}"
                perfil_firma_individual = perfil_firma_final.copy() # objeto nuevo, 1 nivel de profundidad copiado, sin referencias compartidas
                stream_aux = BytesIO()
                rev = BytesIO()

                print()
                logger.info("(%s) Abriendo PDF: '%s'", idx, pdf.name)

                if firmas_previas > 0:
                    logger.info("El PDF posee firmas previas: %s", firmas_previas)
                else:
                    logger.info("El PDF no posee ninguna firma previa.")
                logger.info("Su firma se incrustará en posición: %s", nextsig_visual)

                with open(pdf, 'rb') as f_in:
                    original = IncrementalPdfFileWriter(f_in)
                    if es_pdf_cifrado:
                        original.encrypt(user_pwd="")
                        # TODO: no me termina de agradar. asumimos que el cifrado es "password permissions".

                    try:
                        logger.info("Firmando...")
                        await FIRMANTE.async_sign_pdf(
                            pdf_out=original,
                            output=stream_aux,
                            existing_fields_only=False
                        )
                    except TimestampRequestError as e: # TODO: necesito excepción especifica para cuando la TSA no responde.
                        logger.error('La TSA no ha respondido! (%s)', e)
                        if core_utils.continuar_salir(msj="¿Omitir éste PDF y continuar firmando o salir? (y/n): "):
                            continue
                    except Exception as e: # TODO: necesito excepción especifica para cuando la TSA no responde.
                        logger.warning('Error al firmar PDF "%s": %s', pdf.name, e)
                        if core_utils.continuar_salir(msj="¿Omitir éste PDF y continuar firmando o salir? (y/n): "):
                            continue
                    else:
                        logger.info("Firmado.")
                        
                        # Bifuración con 'stream_aux': La firma escribe en stream_aux, mientras todavia es BytesIO
                        # se retornan los bytes del CMS de la firma apenas hecha para obtener su 'Validation Related
                        # Information (VRI)' e interactuar correctamente con DSS adelante.
                        cms_bytes, vri = pdf_utils.extraer_cms_y_vri(stream=stream_aux, indice=nextsig_interno, usa_cifrado=es_pdf_cifrado)
                        logger.info("Entrada VRI de la firma %s: %s", nextsig_visual, vri)

                        # Retorno del TST de contrafirma en un CMS de pefiles 'T': Se asume que 1 firmante
                        # individual crea 1 CMS con 1 SignerInfo, y si hay timestamping; 1 solo TST en sus
                        # contrafirmas, por lo que no debería ser del todo salvaje numerar en 0 los parametros
                        # signer= y contrafirma= dado que esa es la posición esperada del TST en su CMS.
                        #if FIRMANTE.default_timestamper:
                        if FIRMANTE.default_timestamper:
                            tst_cms = cripto.extraer_tst_cms(cms=cms_bytes, signer=0, contrafirma=0)
                            perfil_firma_individual.append('T')
                            logger.info("Perfil 'Timestamp (T)' completo (TST en CMS).")

                        # Contexto DSS: Retomamos el BytesIO de stream_aux, instanciamos como IncrementalPdfFileWriter()
                        # y agregamos contexto de validación en su DSS: Respuestas OCSP, Certs de DSS y CMS del firmante
                        # para relacionar el contexto con su entrada VRI.
                        firmado = IncrementalPdfFileWriter(stream_aux)
                        if es_pdf_cifrado:
                            firmado.encrypt(user_pwd="") # TODO: no me agrada, asumimos que el cifrado es solo de "password permissions"

                        logger.info("Añadiendo contexto de validación en 'Document Security Store (DSS)'...")
                        dss = DocumentSecurityStore.supply_dss_in_writer(
                            pdf_out=firmado,            # firmado + contexto dss

                            sig_contents=cms_bytes,     # relaciona la VRI en base al CMS en bytes, literalmente: hashlib.sha1(sig_contents).digest().hex().upper()
                            ocsps=ocsp_responses,       # Lista de objetos respuesta asn1crypto.ocsp.OCSPResponse
                            certs=dss_certs,            # lista de objetos asn1crypto.x509.Certificate (firmante, inter, reponder, inter) (sin raices)
                            crls=None                   # CRLs si se tuviesen (de momento queda None hardcodeado)
                        )
                        logger.info("Contexto de validación en DSS añadido.")

                        # TST para perfil A
                        if ts_dss:
                            try:
                                logger.info("Añadiendo TST en '/DocTimeStamp'...")
                                await ts_dss.async_timestamp_pdf(
                                    pdf_out=firmado,                    # entra 'IncrementalPdfFileWriter()'
                                    md_algorithm=TSA["HASH"],
                                    output=rev                          # retorna 'BytesIO'
                                )
                            except TimestampRequestError as e:
                                logger.error('La TSA no ha respondido! (%s)', e)
                                if core_utils.continuar_salir(msj="¿Omitir éste PDF y continuar firmando o salir? (y/n): "):
                                    continue
                            except Exception as e:
                                logger.warning('Error al firmar PDF "%s": %s', pdf.name, e)
                                if core_utils.continuar_salir(msj="¿Omitir éste PDF y continuar firmando o salir? (y/n): "):
                                    continue
                            else:
                                # Retorno del TST de perfiles A: parece salvaje pero para cada sesión de firma la
                                # última firma hecha siempre es el TST de /DocTimeStamp, y dado que este TST no es
                                # una contrafirma (cms anidado), se puede cargar tal cual el PDF como PdfFileReader()
                                # para acceder directo a las "embedded_signatures" tal cual las almacena pyhanko,
                                # con cero-padding al final como en el CMS del firmante.
                                tst_dss = PdfFileReader(rev).embedded_timestamp_signatures[-1].pkcs7_content
                                logger.info("Perfil 'Archival (A)' completo (TST en /DocTimeStamp).")
                                perfil_firma_individual.append('A')
                        else:
                            firmado.write(rev)
                            # 'rev' se entiende como la revisión final del PDF, lo que se escribe al archivo
                            # final. Si hay TST en DSS el método ".timestamp_pdf()" hace internamente la
                            # escritura a rev para incluír el TST en /DocTimeStamp. Si no se usa perfil 'A',
                            # se escribe a rev desde el método ".write()" de los 'IncrementalPdfFileWriter'
                            # desde 'firmado' (que sería "la versión más completa" del pdf que no usa TST
                            # en DSS).
                            # 
                            # Cualquiera que sea el caso, rev se manejará como 'BytesIO' para escribir en él,
                            # leer el historial de firmas antes de cerrar y finalmente pasarlo a bytes para
                            # escribirlo como el archivo PDF final firmado.

                        logger.info("Firma 'PAdES-B-%s' efectuada correctamente.", ''.join(perfil_firma_individual))

                        # Conteo visual de firmas.
                        firmas_totales = pdf_utils.leer_firmas_pdf(pdf_input=rev, usa_cifrado=es_pdf_cifrado)
                        if firmas_totales:
                            logger.info("========== HISTORIAL DE FIRMAS ==========")
                            for n, j in enumerate(iterable=firmas_totales, start=1):
                                logger.info("%s. %s", n, j)
                            logger.info("========== HISTORIAL DE FIRMAS ==========")

                        # Guardado de archivos de cada iteración.
                        core_utils.guardar_archivos(f'{dir_sesion_firma}/(complemento) archivos separados', 'p7s', **{f"{pdf.name}.__CMS":cms_bytes})
                        with open(nombre_pdf_firmado, 'wb') as f_out:
                            f_out.write(rev.getvalue())

                        if tst_cms:
                            core_utils.guardar_archivos(f'{dir_sesion_firma}/(complemento) archivos separados', 'der', **{f"{pdf.name}.__TST_Firma":tst_cms})
                        if tst_dss:
                            core_utils.guardar_archivos(f'{dir_sesion_firma}/(complemento) archivos separados', 'der', **{f"{pdf.name}.__TST_PDF":tst_dss})

                        logger.info("Cerrando PDF: '%s'", pdf.name)

    # Wrap up y resumen de sesión.
    if Path(f'{dir_sesion_firma}/(complemento) archivos separados').is_dir():
        with open(f'{dir_sesion_firma}/(complemento) archivos separados/0disclaimer.txt', 'w') as f:
            f.write(config.MENSAJES_MISC['disclaimer_firmas_separadas'])

    end_time = f"{(perf_counter() - ini_time):.3f}"
    print()
    print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Sesión de firma finalizada.")
    print(f"   • Duración: {end_time}s")
    print(f"   • Total de Firmas: {len(PDFs)}")
    print(f"   • Fecha: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")} (UTC)")
    print(f"   • Ruta Archivos: '{Path(dir_sesion_firma).absolute()}'", end="")
    return

@wrappers.salida_limpia()
def hacer_firma():
    try:
        # 1. Carga inicial y prefirma.
        # Evaluar que el material a firmar sea viable antes de cualquier otra cosa, evidentemente (¬_¬").
        logger.info("Usando configuración por defecto (%s).", usuarios.load_state_users()['principal'])
        PRINCIPAL = usuarios.load_principal_conf()
        pdf_ruta_base = Path(PDF_RUTA_BASE)
        pdfs = []
        normalizados = None

        # se toma todo archivo, se filtra por extensión .pdf (cualquier variante) se calculan y suman por lógica
        # de append las potenciales excepciones que puedan ocurrir por nombre de archivo. De cualquier modo en
        # prefirma se evalua por bytes de header si en efecto son PDFs reales o no y se descartan en consecuencia.
        archivos = [i for i in pdf_ruta_base.iterdir() if i.is_file()] # se recorre el directorio solo 1 vez
        pdfs = [i for i in archivos if i.suffix.lower() == ".pdf"]
        potencial_excepcion = [i for i in archivos if i.suffix.lower() != ".pdf" and i.name.lower().endswith("pdf")]
        pdfs += potencial_excepcion
        if not pdfs:
            logger.warning("No hay material para firmar en: '%s' (,,¬﹏¬,,)!", pdf_ruta_base.absolute())
            logger.warning("Añada uno o más documentos .pdf y empiece a firmar!")
            return False
        pdfs, normalizados = prefirma.prefirmar(lista_pdfs=pdfs, preferencias=PRINCIPAL["preferencias_uso"])
        if not pdfs:
            return False

        # 2. Instanciación de contexto PKI.
        # Si el material a firmar es viable (independientemente de cuanto sea) se instancia el contexto
        # PKI en el que operará el firmante, y se definirá el contexto/configuración de firma del firmante.
        firmante_ctx = contexto(firmante_input=PRINCIPAL)
        if not firmante_ctx:
            return False

        # 3. Si existe firmante instanciado en su contexto PKI y con contexto de firma; se inicia el
        # procedimiento de firma real sobre el material.
        asyncio.run(firma(firmante_ctx=firmante_ctx, pdfs=pdfs))
        #firma(pdfs=pdfs, firmante_ctx=firmante_ctx)

    # cleanup para archivos normalizados estilo trap ... EXIT en bash
    finally:
        # de momento los vamos a borrar, estaría bueno meter en preferencias de uso una opcion bool
        # para dejarlos tras sesión de firma o borrarlos tras sesión de firma.
        if normalizados and not PRINCIPAL["preferencias_uso"]["mantener_normalizados"]:
            print(end="\n\n")
            logger.info("Limpiando archivos normalizados...")
            for i in normalizados:
                i.unlink(missing_ok=True)
        elif normalizados == None:
            pass
        else:
            print()

    # TODO:
    # Se pueden firmar documentos ya firmandos, pero no se pueden solapar los 'field_name' de sigmeta.
    # En caso de que un firmante repita su firma sobre un PDF deben gestionarse los 'field_name' de
    # todos los firmantes repetidos antes de firmar efectivamente.
    # ¿Es un caso de uso común la firma repetida? ¿re-firmar un PDF que uno mismo ya había firmado?

    # TODO:
    # Sería ideal hacer un sistema dinámico de nombrado de PDFs según su cantidad de firmas acumuladas
    # por sesión de firma. En lugar de meter el texto estático "_FIRMADO", se podría agregar algo como:
    # "_revN" donde N sea un número natural positivo icremental según las sesiones de firma totales.

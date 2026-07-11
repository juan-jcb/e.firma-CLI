import logging, getpass
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
from efcli.core import core_utils, wrappers, registros, pki, x509, pkey
from efcli.xdg import xdg_config, usuarios
from efcli.ocsp import fetcher, ocsp_utils
from efcli.pdf import pdf_utils
from efcli.firma import prefirma

logger = logging.getLogger(__name__)

def manejador_ocsp(firmante_crt, firmante_issuer_crt, endpoints: list, pki_ctx, dir_save):
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
    for endpoint in endpoints:
        logger.info("Consultando endpoint: %s", endpoint)
        OCSP_RESPONSE = fetcher.fetch(ocsp_request=OCSP_REQUEST, endpoint=endpoint)
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
                OCSP_CA_CHAIN = [i for i in pki.get_ca_chain(cert=OCSP_RESPONDER_X509, tipo='ocsp_responder', pki_ctx=pki_ctx)]
                #ocsp_root_x509      = OCSP_CA_CHAIN[0]
                #ocsp_inters_x509    = OCSP_CA_CHAIN[-3:0:-1]
                ocsp_issuer_x509    = OCSP_CA_CHAIN[-2]
                ocsp_responder_x509 = OCSP_CA_CHAIN[-1]

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
        core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'pem', responder_x509=pem.armor(der_bytes=ocsp_responder_x509.dump(), type_name="CERTIFICATE"))
        if OCSP_CA_CHAIN:
            core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'pem', responder_cadena=pki.hacer_cadena_pem(chain_path=OCSP_CA_CHAIN, elementos="no_subject"))
            core_utils.guardar_archivos(f'{dir_save}/ocsp_info.{hora}', 'txt', resumen_cadena=pki.leer_ca_chain_simple(chain_path=OCSP_CA_CHAIN).encode('utf-8'))

    return (PERFIL_OCSP, OCSP_RESPONSES, OCSP_X509_DSS)

def contexto(firmante_input: dict, pki_ctx: ValidationContext) -> dict | None:
    FIRMANTE = firmante_input['firmante']
    SIG_META = firmante_input['metadatos_firma']
    PERFILES_FIRMA = firmante_input['perfiles_firma']
    CAMPO_VISUAL = firmante_input['firma_visible']
    BANXICO_PKI_CTX = pki_ctx
    TSA = xdg_config.GLOBAL_CONFIG['TSA']

    PERFIL_FIRMA_PROPUESTO = ['B']

    logger.info("Definiendo al firmante.")
    print("    1. Cargando contexto PKI del firmante...")

    cert, cert_encode = x509.cargar_cert_asn1(cert=FIRMANTE['certificado'])
    print(f"     • Certificado ({cert_encode}) cargado.")

    try:
        # En caso de que metan una CA intermedia nueva no se afecta este código (supuestamente ;-;)
        # dejando como unica acción necesaria la adición explicita del x509 nuevo en docs de PKI.
        SUBJECT_CA_CHAIN = [i for i in pki.get_ca_chain(cert=cert, tipo='firmante', pki_ctx=BANXICO_PKI_CTX)]

        #X509_ROOT     = SUBJECT_CA_CHAIN[0]       # aunque se tiene acceso a su x509, la raíz se asume en el validador.
        SUBJECT_INTERS = SUBJECT_CA_CHAIN[-3:0:-1] # slice invertido para incluir (desde -3) n cantidad de CAs intermedias sin raíz
        X509_ISSUER    = SUBJECT_CA_CHAIN[-2]
        X509_SUBJECT   = SUBJECT_CA_CHAIN[-1]

        subject_certs = [X509_ISSUER]

        # si agregasen más CAs se distribuirán dinámicamente aquí. 'SUBJECT_INTERS' será lista vacia hasta
        # que exista un elemento nuevo en indice de CA intermedia.
        if SUBJECT_INTERS:
            subject_certs += [i for i in SUBJECT_INTERS]

    except Exception:
        logger.error("No se puede establecer el contexto PKI del firmante.")
        print('Saliendo...')
        return False
    else:
        print("     • Cadena de confianza establecida.")

    print("\n    2. Cargando clave privada del firmante...")
    res, tipo_pkey = pkey.es_pkey_cifrada(ruta_pkey=FIRMANTE['clave_privada'])
    if res == True:
        print("     • Clave privada cifrada.")
        while True:
            pkey_passwd = getpass.getpass(prompt="     • Contraseña: ", echo_char="*").encode('utf-8')
            if pkey.es_passwd_de_pkey(ruta_pkey=FIRMANTE['clave_privada'], tipo_encode=tipo_pkey, passwd=pkey_passwd):
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
            key_file=FIRMANTE['clave_privada'],
            key_passphrase=pkey_passwd,
            cert_file=FIRMANTE['certificado'],

            other_certs=subject_certs,  # "Certificates" en el CMS. Mientras el orden aquí sea CONSTANTE, /Certs de /DSS será congruente.
                                        # Al definir al firmante se entiende en este parametro: [X509_SUBJECT, X509_ISSUER]

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
            field_name=SIG_META['nombre_firma'],

            name=SIG_META['nombre_firmante'],
            reason=SIG_META['razon'],
            location=SIG_META['lugar'],
            contact_info=SIG_META['contacto'],
            md_algorithm=TSA['CMS_HASH'],
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
        print(f"     • ID Firma:  {SIG_META['nombre_firma']}")
        print(f"     • Nombre:    {SIG_META['nombre_firmante']}")
        print(f"     • Razón:     {SIG_META['razon']}")
        print(f"     • Lugar:     {SIG_META['lugar']}")
        print(f"     • Contacto:  {SIG_META['contacto']}")

    print("\n    4. Cargando contexto opcional de la firma...")
    # OCSP para estado del firmante (perfil 'L')
    if PERFILES_FIRMA['OCSP'] == True:
        print(f"     • Se utilizará OCSP '{xdg_config.GLOBAL_CONFIG['OCSP']['endpoints'][0]}' para validación externa (Fallbacks: {len(xdg_config.GLOBAL_CONFIG['OCSP']['endpoints'])-1}).")
        PERFIL_FIRMA_PROPUESTO[0] = 'L'
    else:
        print('     • NO se utilizará OCSP para validar su certificado X.509.')

    # TST en CMS (perfil 'T')
    if PERFILES_FIRMA['TST_CMS'] == True:
        try:
            firmante_simple_ts_cms = timestamps.HTTPTimeStamper(url=TSA['CMS_URI'])
        except Exception:
            logger.warning("No se pudo configurar timestamp para CMS. Continuando sin el...")
            firmante_simple_ts_cms = None
        else:
            print(f"     • Se utilizará TSA '{TSA['CMS_URI']}' para timestamping en su firma (CMS).")
            PERFIL_FIRMA_PROPUESTO.append('T')
    else:
        print('     • NO se utilizará TSA para timestamping en su firma (CMS).')
        firmante_simple_ts_cms = None

    # TST en DSS /DocTimeStamp (perfil 'A')
    if PERFILES_FIRMA['TST_DSS'] == True:
        try:
            http_ts_dss = timestamps.HTTPTimeStamper(url=TSA['DSS_URI'])
            ts_dss = signers.PdfTimeStamper(timestamper=http_ts_dss)
        except Exception:
            logger.warning("No se pudo configurar timestamp en PDF (/DocTimeStamp). Continuando sin el...")
            ts_dss = None
        else:
            print(f"     • Se utilizará TSA '{TSA['DSS_URI']}' para timestamping en PDF (/DocTimeStamp).")
            PERFIL_FIRMA_PROPUESTO.append('A')
    else:
        print('     • NO se utilizará TSA para timestamping en PDF (/DocTimeStamp).')
        ts_dss = None

    # Campo de firma visual en PDF
    if CAMPO_VISUAL['usar'] == True:
        print("     • Configurando CAMPO visible de la firma...")
        #coords_x = 50
        #coords_y = 50
        ancho = 200
        alto = 50

        try:
            campo_visual = fields.SigFieldSpec(
                sig_field_name=SIG_META['nombre_firma'],
                on_page=CAMPO_VISUAL['pagina'],

                box=(
                    CAMPO_VISUAL['coords_x'],
                    CAMPO_VISUAL['coords_y'],
                    CAMPO_VISUAL['coords_x'] + ancho,
                    CAMPO_VISUAL['coords_y'] + alto,
                )
            )
        except Exception as e:
            logger.error("Fallo al configurar el CAMPO visible de la firma. (%s)", e)
            return False
    else:
        print('     • NO se utilizará CAMPO para firma visible en PDF.')
        campo_visual = None

    # Instanciación de objeto "firmante de pdf" en la clase encapsuladora PdfSigner con las opciones acumuladas.
    try:
        firmante_pdf = signers.PdfSigner(
            signer=firmante_simple,
            signature_meta=firmante_simple_sigmeta,
            timestamper=firmante_simple_ts_cms,
            new_field_spec=campo_visual,
        )
    except Exception as e:
        print(e)
        return False
    else:
        print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Firmante y contexto operacional listo.")

    # Mensajes últimos de desglose y prompt de confirmación.
    print()
    logger.info("Firmante: %s", x509.leer_subject_simple(cert=X509_SUBJECT))
    logger.info("Perfil de firma propuesto: PAdES-B-%s", ''.join(PERFIL_FIRMA_PROPUESTO))
    #print(f'\n• Documentos a firmar: {PDFs}')
    #print(pki.leer_ca_chain_simple(chain_path=CA_CHAIN_SUBJECT))

    if PERFILES_FIRMA['OCSP'] == True:
        print(f"\n{config.MENSAJES_MISC['msj_desfase_temporal']}")

    core_utils.continuar_salir(msj='\n¿Proceder y firmar? (y/n): ')

    firmante_ctx = {
        'firmante': firmante_pdf,
        'firmante_ca_chain': SUBJECT_CA_CHAIN,
        'perfiles_firma': PERFILES_FIRMA,

        'tst_dss_timestamper': ts_dss,
        'tst_dss_hash': TSA['DSS_HASH'],

        'contexto_pki': BANXICO_PKI_CTX,
    }

    return firmante_ctx

def firma(firmante_ctx: dict, pdfs: list) -> None:
    '''
    Firmar digitalmente un PDF. Firmante Individual.
    Operaciones dependientes de desfase temporal.
    '''
    USUARIO_PRINCIPAL = usuarios.load_state_users()['principal']
    RUTA_BASE = xdg_config.GLOBAL_CONFIG['pdf_ruta_base']
    DIR_SESION_FIRMA = Path(f'{RUTA_BASE}/({USUARIO_PRINCIPAL}) Sesión de Firma - {datetime.now().strftime("%a %b %d %I:%M:%S %p %Y")}')

    BANXICO_PKI_CTX = firmante_ctx['contexto_pki']
    FIRMANTE = firmante_ctx['firmante']
    FIRMANTE_CA_CHAIN = firmante_ctx['firmante_ca_chain']
    PERFIL_FIRMA_INICIAL = ['B']

    USAR_OCSP = firmante_ctx['perfiles_firma']['OCSP']
    OCSP_URIS = xdg_config.GLOBAL_CONFIG['OCSP']['endpoints']
    OCSP_RESPONSES = None
    TIMER_OCSP = False

    TST_CMS = None
    TST_DSS = None
    DSS_TIMESTAMPER = firmante_ctx['tst_dss_timestamper']
    DSS_TIMESTAMP_HASH = firmante_ctx['tst_dss_hash']

    PDFs = pdfs
    L_PDFS = len(PDFs)

    # /Certs de /DSS
    # El llenado de objetos certificado de la lista DSS_CERTS se prefiere en órden: [end, inter, inter, ...] SIN RAÍZ
    # para estár en conformidad con "ETSI EN 319 102-1 y 319 122-1 PAdES"
    # - Se empieza a llenar por el certificado del firmante y hasta N cantidad de sus CAs intermedias desde su
    #   atributo cert_registry.
    # - Posteriormente en caso de utilizar validación OCSP e incluir certificados x509 del responder, el orden
    #   de llenado continua en lógica de .append(): [end, inter, inter, ..., ocsp, inter, inter, ...] de igual
    #   forma sin incluír la raíz de ninguna entidad final ya que se asume esta existirá en el validador.
    DSS_CERTS = [FIRMANTE.signer.signing_cert]
    for i in FIRMANTE.signer.cert_registry.certs.values():
        DSS_CERTS.append(i)

    print()
    logger.info("Iniciando sesión de firma.")
    DIR_SESION_FIRMA.mkdir(parents=True)
    core_utils.guardar_archivos(f'{DIR_SESION_FIRMA}/firmante_info', 'txt', resumen_cadena=pki.leer_ca_chain_simple(chain_path=FIRMANTE_CA_CHAIN).encode('utf-8'))
    core_utils.guardar_archivos(
        f'{DIR_SESION_FIRMA}/firmante_info', 'pem',
        firmante_x509=pem.armor(der_bytes=FIRMANTE.signer.signing_cert.dump(), type_name="CERTIFICATE"),
        firmante_cadena=pki.hacer_cadena_pem(chain_path=FIRMANTE_CA_CHAIN, elementos="no_subject")
    )
    ini_time = perf_counter()

    with registros.modded_logs(target_logger=logger, fmt="[%(levelname)s] (%(asctime)s) %(message)s"):
        if USAR_OCSP == True:
            print()
            logger.info("Iniciando validación externa mediante 'Online Certificate Status Protocol (OCSP)'.")
            perfil_ocsp, OCSP_RESPONSES, ocsp_x509_dss = manejador_ocsp(
                firmante_crt=DSS_CERTS[0],
                firmante_issuer_crt=DSS_CERTS[1],
                endpoints=OCSP_URIS,
                pki_ctx=BANXICO_PKI_CTX,
                dir_save=DIR_SESION_FIRMA
            )
            if ocsp_x509_dss:
                DSS_CERTS += ocsp_x509_dss
            if perfil_ocsp:
                PERFIL_FIRMA_INICIAL[0] = perfil_ocsp[0]

            # Por más pocho que sea el hardware 150 firmas en perfil alto no sobrepasan los 5 minutos, sería a partir
            # de 150 pdfs a firmar que empezariamos a usar la comparación por tiempo en cada iteración de firma para
            # evaluar si el tiempo transcurrido bajo perfil L sobrepasa 295 segundos (casi 5min) y así realizar una
            # nueva petición OCSP y continuar firmando bajo la misma lógica ordenada.
            if L_PDFS > 150:
                TIMER_OCSP = True
                techo_ocsp = 295
                ocsp_time = perf_counter()

        # Bucle de firma sobre los PDFs.
        for i in PDFs: # tuplas de 3 elementos: ("Path del PDF", "bool de cifrado", "int de siguiente firma disponible").
            if TIMER_OCSP:
                # si se firman menos de 150 pdfs: if false, no baja rendimiento.
                # si se firman más de 150 pdfs: if true, se compara tiempo en cada iteración para gestionar a mano el nextUpdate.
                if (perf_counter() - ocsp_time) > techo_ocsp:
                    print()
                    PERFIL_FIRMA_INICIAL = ['B']
                    logger.warning("ATENCIÓN!, Se ha sobrepasado el techo práctico de tiempo para seguir usando la misma respuesta OCSP.")
                    logger.warning("Se realizará una NUEVA petición OCSP a los endpoints por defecto para corroborar nuevamente el estado del firmante.\n")
                    sleep(3)

                    logger.info("Iniciando nuevamente validación externa mediante 'Online Certificate Status Protocol (OCSP)'.")
                    perfil_ocsp, OCSP_RESPONSES, ocsp_x509_dss = manejador_ocsp(
                        firmante_crt=DSS_CERTS[0],
                        firmante_issuer_crt=DSS_CERTS[1],
                        endpoints=OCSP_URIS,
                        pki_ctx=BANXICO_PKI_CTX,
                        dir_save=DIR_SESION_FIRMA
                    )
                    if ocsp_x509_dss: # volvemos a llenar DSS_CERTS: el firmante no cambia y quita N certs del responder anterior.
                        DSS_CERTS = [FIRMANTE.signer.signing_cert]
                        for j in FIRMANTE.signer.cert_registry.certs.values():
                            DSS_CERTS.append(j)
                        DSS_CERTS += ocsp_x509_dss
                    if perfil_ocsp:
                        PERFIL_FIRMA_INICIAL[0] = perfil_ocsp[0]
                        techo_ocsp += 298
                    else:
                        TIMER_OCSP = False
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

            nombre_pdf_firmado = f"{DIR_SESION_FIRMA}/{pdf.stem}_FIRMADO{pdf.suffix}"
            perfil_firma_individual = PERFIL_FIRMA_INICIAL
            stream_aux = BytesIO()
            rev = BytesIO()

            print()
            logger.info("Abriendo PDF: '%s'", pdf.name)

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
                    FIRMANTE.sign_pdf(
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

                    # Retorno del TST de contrafirma en un CMS de pefiles 'T': Se asume que 1 firmante
                    # individual crea 1 CMS con 1 SignerInfo, y si hay timestamping; 1 solo TST en sus
                    # contrafirmas, por lo que no debería ser del todo salvaje numerar en 0 los parametros
                    # signer= y contrafirma= dado que esa es la posición esperada del TST en su CMS.
                    if FIRMANTE.default_timestamper:
                        TST_CMS = pkey.extraer_tst_signer(cms=cms_bytes, signer=0, contrafirma=0)
                        perfil_firma_individual.append('T')
                        logger.info("Perfil 'Timestamp (T)' completo (TST en CMS).")
                    
                    # Bifuración con 'stream_aux': La firma escribe en stream_aux, mientras todavia es BytesIO
                    # se retornan los bytes del CMS de la firma apenas hecha para obtener su 'Validation Related
                    # Information (VRI)' e interactuar correctamente con DSS adelante.
                    cms_bytes, vri = pdf_utils.extraer_cms_y_vri(stream=stream_aux, indice=nextsig_interno, usa_cifrado=es_pdf_cifrado)
                    logger.info("Entrada VRI de la firma %s: %s", nextsig_visual, vri)

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
                        ocsps=OCSP_RESPONSES,       # Lista de objetos respuesta asn1crypto.ocsp.OCSPResponse
                        certs=DSS_CERTS,            # lista de objetos asn1crypto.x509.Certificate (firmante, inter, reponder, inter) (sin raices)
                        crls=None                   # CRLs si se tuviesen (de momento queda None hardcodeado)
                    )
                    logger.info("Contexto de validación en DSS añadido.")

                    # TST para perfil A
                    if DSS_TIMESTAMPER:
                        logger.info("Añadiendo TST en '/DocTimeStamp'...")
                        DSS_TIMESTAMPER.timestamp_pdf(
                            pdf_out=firmado,                    # entra 'IncrementalPdfFileWriter()'
                            md_algorithm=DSS_TIMESTAMP_HASH,

                            output=rev                          # retorna 'BytesIO'
                        )

                        # Retorno del TST de perfiles A: parece salvaje pero para cada sesión de firma la
                        # última firma hecha siempre es el TST de /DocTimeStamp, y dado que este TST no es
                        # una contrafirma (cms anidado), se puede cargar tal cual el PDF como PdfFileReader()
                        # para acceder directo a las "embedded_signatures" tal cual las almacena pyhanko,
                        # con cero-padding al final como en el CMS del firmante.
                        TST_DSS = PdfFileReader(rev).embedded_timestamp_signatures[-1].pkcs7_content

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
                    core_utils.guardar_archivos(f'{DIR_SESION_FIRMA}/(complemento) archivos separados', 'p7s', **{f"{pdf.name}.CMS":cms_bytes})
                    with open(nombre_pdf_firmado, 'wb') as f_out:
                        f_out.write(rev.getvalue())

                    if TST_CMS:
                        core_utils.guardar_archivos(f'{DIR_SESION_FIRMA}/(complemento) archivos separados', 'der', **{f"{pdf.name}.TST-Firma":TST_CMS})
                    if TST_DSS:
                        core_utils.guardar_archivos(f'{DIR_SESION_FIRMA}/(complemento) archivos separados', 'der', **{f"{pdf.name}.TST-PDF":TST_DSS})

                    logger.info("Cerrando PDF: '%s'", pdf.name)

    # Wrap up y resumen de sesión.
    if Path(f'{DIR_SESION_FIRMA}/(complemento) archivos separados').is_dir():
        with open(f'{DIR_SESION_FIRMA}/(complemento) archivos separados/0disclaimer.txt', 'w') as f:
            f.write(config.MENSAJES_MISC['disclaimer_firmas_separadas'])

    end_time = f"{(perf_counter() - ini_time):.3f}"
    print()
    print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Sesión de firma finalizada.")
    print(f"   • Duración: {end_time}s")
    print(f"   • Total de Firmas: {len(PDFs)}")
    print(f"   • Fecha: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")} (UTC)")
    print(f"   • Ruta Archivos: '{Path(DIR_SESION_FIRMA).absolute()}'", end="")
    return

@wrappers.salida_limpia()
def hacer_firma():
    try:
        xdg_config.load_global()
        PRINCIPAL = usuarios.load_principal_conf()

        logger.info("Usando configuración por defecto (%s).", usuarios.load_state_users()['principal'])

        # 1. Carga inicial y prefirma.
        # Evaluar que el material a firmar sea viable antes de cualquier otra cosa, evidentemente (¬_¬").
        pdf_ruta_base = Path(xdg_config.GLOBAL_CONFIG['pdf_ruta_base'])
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
        pki_ctx = pki.get_validation_context(
            trust_roots=xdg_config.GLOBAL_CONFIG['PKI']['trust_roots'],
            intermediate_cas=xdg_config.GLOBAL_CONFIG['PKI']['intermediate_cas'],
        )
        firmante_ctx = contexto(
            firmante_input=PRINCIPAL,
            pki_ctx=pki_ctx
        )
        if not firmante_ctx:
            return False

        # 3. Si existe firmante instanciado en su contexto PKI y con contexto de firma; se inicia el
        # procedimiento de firma real sobre el material.
        firma(pdfs=pdfs, firmante_ctx=firmante_ctx)

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

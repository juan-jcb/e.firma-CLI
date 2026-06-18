import logging, getpass
from io import BytesIO
from pathlib import Path
from time import perf_counter
from datetime import datetime, timezone
from colorama import Fore

from asn1crypto import pem, x509 as asn1_x509
from pyhanko.sign import signers, fields, timestamps
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

from efcli.pdf import integridad_pdfs, pdf_utils
from efcli.pki import pki, ocsp, x509_utils
from efcli.utils import cripto, general, registros, wrappers
from efcli import config

logger = logging.getLogger(__name__)

@wrappers.salida_limpia()
def contexto(firmante_input: dict, pki_ctx: ValidationContext) -> dict | None:
    BANXICO_PKI_CTX = pki_ctx
    FIRMANTE = firmante_input['firmante']
    SIG_META = firmante_input['metadatos_firma']
    CAMPO_VISUAL = firmante_input['firma_visible']
    PREFERENCIAS = firmante_input['preferencias']
    PERFIL_FIRMA_PROPUESTO = ['B']

    TSA = config.GLOBAL_CONFIG['TSA']

    logger.info("Definiendo al firmante.")
    print("    1. Cargando contexto PKI del firmante...")
    
    cert, cert_encode = x509_utils.cargar_cert_asn1(cert=FIRMANTE['certificado'])
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
    res, tipo_pkey = cripto.es_pkey_cifrada(pkey=FIRMANTE['clave_privada'])
    if res == True:
        print("     • Clave privada cifrada.")
        while True:
            pkey_passwd = getpass.getpass(prompt="     • Contraseña: ", echo_char="*").encode('utf-8')
            if cripto.es_passwd_de_pkey(ruta_pkey=FIRMANTE['clave_privada'], tipo_encode=tipo_pkey, passwd=pkey_passwd):
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
    if PREFERENCIAS['OCSP'] == True:
        print(f"     • Se utilizará OCSP '{config.GLOBAL_CONFIG['OCSP']['endpoints'][0]}' para validación externa (Fallbacks: {len(config.GLOBAL_CONFIG['OCSP']['endpoints'])-1}).")
        PERFIL_FIRMA_PROPUESTO[0] = 'L'
    else:
        print('     • NO se utilizará OCSP para validar su certificado X.509.')
    
    # TST en CMS (perfil 'T')
    if PREFERENCIAS['TST_CMS'] == True:
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
    if PREFERENCIAS['TST_DSS'] == True:
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
    logger.info("Firmante: %s", x509_utils.leer_subject_simple(cert=X509_SUBJECT))
    logger.info("Perfil de firma propuesto: PAdES-B-%s", ''.join(PERFIL_FIRMA_PROPUESTO))
    #print(f'\n• Documentos a firmar: {PDFs}')
    #print(pki.leer_ca_chain_simple(chain_path=CA_CHAIN_SUBJECT))
    
    if PREFERENCIAS['OCSP'] == True:
        print(f"\n{config.MENSAJES_MISC['msj_desfase_temporal']}")
    
    print()
    while True:
        opcion = input('¿Proceder y firmar? (y/n): ')
        if opcion == 'y':
            print('Continuando...')
            break
        elif opcion == 'n':
            print('Saliendo...')
            return False
        else:
            print('Ingrese una opción correcta.')

    firmante_ctx = {
        'contexto_pki': BANXICO_PKI_CTX,
        
        'firmante': firmante_pdf,
        'firmante_ca_chain': SUBJECT_CA_CHAIN,

        'tst_dss_hash': TSA['DSS_HASH'],
        'tst_dss_timestamper': ts_dss,
        'campo_visual': campo_visual,

        'preferencias': PREFERENCIAS
    }

    return firmante_ctx

def firma(pdfs: list, firmante_ctx: dict):
    '''
    Firmar digitalmente un PDF. Firmante Individual.
    Operaciones dependientes de desfase temporal.
    '''
    RUTA_BASE = config.GLOBAL_CONFIG['pdf_ruta_base']
    DIR_SESION_FIRMA = Path(f'{RUTA_BASE}/Sesión de Firma - {datetime.now().strftime("%a %b %d %I:%M:%S %p %Y")}')
    DIR_SESION_FIRMA.mkdir(parents=True)
    PDFs = pdfs

    FIRMANTE = firmante_ctx['firmante']
    FIRMANTE_CA_CHAIN = firmante_ctx['firmante_ca_chain']
    PERFIL_FIRMA = ['B']

    BANXICO_PKI_CTX = firmante_ctx['contexto_pki']
    USAR_OCSP = firmante_ctx['preferencias']['OCSP']
    OCSP_URIS = config.GLOBAL_CONFIG['OCSP']['endpoints']
    OCSP_RESPONSES = None
    OCSP_INFO = None

    DSS_TIMESTAMPER_HASH = firmante_ctx['tst_dss_hash']
    DSS_TIMESTAMPER = firmante_ctx['tst_dss_timestamper']    
    TST_CMS = None
    TST_DSS = None

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
    ini_time = perf_counter()
    with registros.log_format(target_logger=logger, fmt="[%(levelname)s] (%(asctime)s) %(message)s"):

        if USAR_OCSP == True:
            print()
            logger.info("Iniciando validación externa mediante 'Online Certificate Status Protocol (OCSP)'.")
            ocsp_request = ocsp.coinstruir_OCSPRequest(cert_client=DSS_CERTS[0], cert_issuer=DSS_CERTS[1])
            # Siempre que el llenado sea constante en DSS_CERTS el indice 0 y el 1 corresponden a firmante y su issuer.

            # No me termina de agradar esta estructura
            for endpoint in OCSP_URIS:
                logger.info("Consultando endpoint: %s", endpoint)
                ocsp_response = ocsp.fetch_ocsp(ocsp_request=ocsp_request, endpoint=endpoint)
                if ocsp_response:
                    logger.info("Respuesta obtenida.")
                    estado = ocsp_response['response_bytes']['response'].parsed['tbs_response_data']['responses'][0]['cert_status']
                    break
                else:
                    print()

            if not ocsp_response:
                logger.error("Han fallado todos los servidores OCSP. Esto AFECTA DIRECTAMENTE al perfil de validación 'Long-Term (L)'.")
                logger.error("Tiene 2 opciones:")
                logger.error("  1. Continuar firma pero SIN validación OCSP externa; el perfil de firma se mantendrá en 'Basic (B)'.")
                logger.error("  2. Cancelar el proceso, esperar un par de minutos a que se regularice el estado del responder y volver a intentar.")
                try:
                    while True:
                        opcion = input('\n¿Continuar con el proceso de firma? (y/n): ')
                        if 'y' in opcion:
                            print("Continuando...")
                            break
                        elif 'n' in opcion:
                            DIR_SESION_FIRMA.rmdir()
                            print("Saliendo...")
                            return False
                        else:
                            print('Ingrese una opción correcta.')
                except KeyboardInterrupt:
                    print("\nSaliendo...")
                    return False

            elif ocsp_response and estado.name == "good":
                logger.info("Certificado X.509 válido en PKI (Cert Status: %s).", estado.name)
                # TODO:
                # Aunque se almacene la respuesta OCSP antes del bucle de firmado y se use el mismo objeto respuesta en
                # todas las firmas (emulando una suerte de cacheado), se debería agregar lógica para manejo del limite
                # temporal de la respuesta recibida si es que se excede el techo práctico para usar la misma respuesta
                # en todas las firmas (nextUpdate o 5min).
                # No es algo muy común que digamos porque las firmas ocurren en intervalos menores al minuto incluso en
                # perfiles altos con latencia extra, pero sigue siendo un caso posible a considerar en el supuesto de
                # que se realicen +50 firmas de con perfiles 'TA' en la misma sesisón.

                # /OCSPs de /DSS recibe 'lista de objetos respuesta', no objetos respuesta solos.
                OCSP_RESPONSES = [ocsp_response] 

                # Recuperación del certificado x509 del responder desde su respuesta.
                logger.info("(Si existiese) Recuperando x509 del responder...")
                ocsp_raw_response = ocsp_response.dump()
                responder_x509 = ocsp.extraer_x509_responder(raw_response=ocsp_raw_response)

                if isinstance(responder_x509, asn1_x509.Certificate):
                    logger.info('Responder incluyó su x509 en la respuesta: "%s" ', x509_utils.leer_subject_simple(cert=responder_x509))
                    logger.info("Se adjuntará también como contexto en /Certs de /DSS).")

                    OCSP_INFO = True
                    DSS_CERTS.append(responder_x509)

                    # Si existe x509 del responder se buscará construír su cadena completa en este contexto PKI y se añadirán
                    # los certificados de sus CAs intermedias (según aplique) en /Certs de /DSS en el orden antes propuesto:
                    # responder, issuer, issuer, ... (sin raíz)
                    logger.info("Reconstruyendo cadena de confianza del responder...")
                    try:
                        OCSP_CA_CHAIN = [i for i in pki.get_ca_chain(cert=responder_x509, tipo='ocsp_responder', pki_ctx=BANXICO_PKI_CTX)]

                        #X509_OCSP_ROOT      = OCSP_CA_CHAIN[0]
                        OCSP_INTERS         = OCSP_CA_CHAIN[-3:0:-1]
                        X509_OCSP_ISSUER    = OCSP_CA_CHAIN[-2]
                        #X509_OCSP_RESPONDER = OCSP_CA_CHAIN[-1]

                        # TODO: Aquí no es ncesario desglosar con 'if OCSP_INTERS:' ???

                    except Exception:
                        logger.warning("No se pudo cargar la cadena de certificados del responder. Continuando sin ellos...")

                    else:
                        logger.info("Cadena del responder OCSP cargada.")

                        # Una vez con la cadena completa del responder se debe evaluar si existe duplicado de Isusers (que el
                        # issuer del responder sea el mismo del firmante) dado que es la topología esperada en la mayoría de
                        # casos, y afortunadamente banxico sí lo hace de forma estándar y define los x509 de responder y los
                        # FIEL/SELLO al mismo nivel jerarquico en su PKI (ambos como end-entities).
                        # 
                        # En caso de ser mismo issuer se añade solo 1 x509 a /CERTS:        [end, end_issuer, ocsp]
                        # Si son issuers diferentes se añade N cantidad en orden normal:    [end, end_issuer, ocsp, ocsp_issuer]

                        if X509_OCSP_ISSUER.dump() == DSS_CERTS[1].dump():
                            logger.info("Firmante y responder comparten MISMO Issuer.")
                            logger.info("Se incluirá el mismo x509 de issuer en /Certs (valida para ambos, evita duplicados).")
                        else:
                            logger.warning("Firmante y responder tienen DISTINTO Issuer.")
                            logger.info("Se incluirán los x509 de cada issuer en /Certs como contexto de validación.")
                            DSS_CERTS.append(X509_OCSP_ISSUER)

                            # TODO:
                            # Solo se está incluyendo el issuer del responder pero no un factible "N cantidad de intermedias"

                            # la práctica correcta es incluir en /Certs el x509 del responder, independientemente de si este
                            # ya está incluído en la respuesta OCSP y por ende en /OCSPs. La duplicidad de datos no viola
                            # ninguna norma y garantiza que el documento sea validable sin conexión ahora y en el futuro.

                            # - Una firma PAdES-LT/LTA exige que la cadena de validación sea autocontenida. El validador
                            #   no debe necesitar conexión a internet para reconstruirla.
                            # - El estándar ETSI EN 319 102-1 §5.5 indica que todos los certificados necesarios para
                            #   validar los materiales de revocación deben estar presentes en /Certs.
                            # - Los validadores (DSS de la Comisión Europea) buscan certificados en /Certs directamente;
                            #   no todos implementan extracción desde la respuesta OCSP.

                            # Respuesta OCSP en /OCSPs
                            # └── BasicOCSPResponse
                            #     └── certs[]   ← certificado del responder (opcional, RFC 6960)
                            # 
                            # /Certs            ← debe incluirse también explícitamente

                            # En general se entiende la estructura:
                            #
                            # /DSS
                            # ├── /Certs
                            # │   ├── Certificado del firmante
                            # │   ├── CA intermedia(s)
                            # │   ├── CA raíz (opcional pero recomendado)
                            # │   └── Certificado del OCSP Responder        ← Incluír siempre aunque ya esté en la respuesta OCSP
                            # │
                            # ├── /OCSPs
                            # │   └── BasicOCSPResponse que puede o no contener internamente el x509 del responder
                            # │
                            # └── /CRLs
                            #     └── (si aplicase)

                            # Referencias normativas.
                            # 
                            # RFC 6960 – Online Certificate Status Protocol (OCSP)
                            # ETSI EN 319 102-1 – Procedures for Creation and Validation of AdES Digital Signatures
                            # ETSI EN 319 122-1 – CAdES (la base de PAdES)
                            # ISO 32000-2 – PDF 2.0, estructura del diccionario DSS

                        PERFIL_FIRMA[0] = 'L'
                        logger.info("Perfil 'Long-Term (L)' completo. (validación externa)")

                else:
                    logger.warning("NO hay certificados x509 incluidos en la respuesta del responder. Continuado sin el...")
            
            elif ocsp_response and estado.name == "revoked":
                # Aunque certs estén expirados el responder marca "revoked" e incluye data de revocación extra que no viene en "good"
                
                # TODO:
                # Se entra a este bloque unicamente cuando el certificado del firmante no ha expirado pero si ha
                # sido revocado en su PKI, no entra cuando el certificado está expirado directamente por fecha.
                # ¿Debería ignorar la restricción (hecha en local) de expiración de certificado al construir su
                # cadena de validación para que deliberadamente se puedan enviar peticiones ocsp de certificados
                # ya expirados y en ambos resultados (revocado y expirado) y se unifiquen los flujos aquí?

                print()
                logger.error("Certificado X.509 REVOCADO.")
                logger.error("Revocado desde: %s (UTC)", estado.chosen['revocation_time'].native.strftime("%Y-%m-%dT%H:%M:%SZ"))
                logger.error("(opcional) Razón: %s", estado.chosen['revocation_reason'].native)
                logger.error("DEBE regularizar su estado con su CA emisora.")
                print()
                logger.warning("Es técnicamente posible continuar con la firma pero bajo su propio criterio.")
                logger.warning("Tiene 2 opciones:")
                logger.warning("  1. Firmar en estado revocado, lo cual será *VISIBLE* en todas sus firmas y mantendrá el perfil en 'Basic (B)'.")
                logger.warning("  2. Cancelar el proceso e intentar nuevamente una vez haya regularizado su situación.")
                try:
                    while True:
                        opcion = input('\n¿Continuar con el proceso de firma? (y/n): ')
                        if 'y' in opcion:
                            print("Continuando...")
                            break
                        elif 'n' in opcion:
                            DIR_SESION_FIRMA.rmdir()
                            print("Saliendo...")
                            return False
                        else:
                            print('Ingrese una opción correcta.')
                except KeyboardInterrupt:
                    print("\nSaliendo...")
                    return False

        # Firma en bucle sobre los PDFs. Todos los iteradores son tuplas: (objeto "Path del PDF", int "siguiente indice disponible").
        for i in PDFs:
            PDF = i[0]
            NOMBRE_PDF_FIRMADO = f"{DIR_SESION_FIRMA}/{PDF.stem}_FIRMADO{PDF.suffix}"
            PERFIL_FIRMA_INDIVIDUAL = PERFIL_FIRMA
            STREAM_AUX = BytesIO()
            REV = BytesIO()

            # Manejo diferenciado entre indice de lista e indice mostrado en terminal
            nextsig_interno = i[1]
            nextsig_visual = i[1] + 1
            if nextsig_interno == 0:
                firmas_previas = 0
            else:
                firmas_previas = nextsig_visual - 1

            print()
            logger.info("Abriendo PDF: '%s'", PDF.name)

            if firmas_previas > 0:
                logger.info("El PDF posee firmas previas: %s", firmas_previas)
            else:
                logger.info("El PDF no posee ninguna firma previa.")
            logger.info("Su firma se incrustará en posición: %s", nextsig_visual)

            with open(PDF, 'rb') as f_in:

                original = IncrementalPdfFileWriter(f_in)
                try:
                    # TODO:
                    # meter try para continuar o salir por si me banean de la TSA (perfiles 'T', 'A') y se interrumpe la iteración actual

                    logger.info("Firmando...")
                    FIRMANTE.sign_pdf(
                        pdf_out=original,
                        output=STREAM_AUX,
                        existing_fields_only=False,
                    )

                except Exception as e:
                    logger.warning('Error al firmar PDF "%s": %s', i, e)
                    return False

                else:
                    # Bifuración sobre el PDF firmado usando 'STREAM_AUX' para leerlo como 'PdfFileReader', retornar
                    # los bytes del CMS de la firma apenas hecha, obtener su 'Validation Related Information (VRI)'
                    # e interactuar cómodamente con /DSS.
                    logger.info("Firmado.")
                    firmado = IncrementalPdfFileWriter(STREAM_AUX)
                    cms_bytes, vri = pdf_utils.extraer_cms_y_vri(stream=STREAM_AUX, indice=nextsig_interno)
                    logger.info("VRI de firma %s: %s", nextsig_visual, vri)

                    # Retornar TSTInfo desde un CMS firmado en pefil 'T'
                    # Se asume que 1 firmante individual crea 1 CMS con 1 SignerInfo, y si hay timestamping; 1 solo TST
                    # en sus contrafirmas, por lo que no debería ser del todo salvaje numerar en 0 los parametros
                    # signer= y contrafirma= dado que esa es la posición esperada del TSTInfo en su CMS.
                    if FIRMANTE.default_timestamper:
                        TST_CMS = cripto.extraer_tst_signer(cms=cms_bytes, signer=0, contrafirma=0)
                        PERFIL_FIRMA_INDIVIDUAL.append('T')
                        logger.info("Perfil 'Timestamp (T)' completo. (TST en CMS)")

                    # Contexto DSS post-firma.
                    logger.info("Añadiendo contexto de validación en 'Document Security Store (DSS)'...")
                    dss = DocumentSecurityStore.supply_dss_in_writer(
                        pdf_out=firmado,

                        sig_contents=cms_bytes,     # relaciona la VRI en base al CMS en bytes, literalmente: hashlib.sha1(sig_contents).digest().hex().upper()
                        ocsps=OCSP_RESPONSES,       # Lista de objetos respuesta asn1crypto.ocsp.OCSPResponse
                        certs=DSS_CERTS,            # lista de objetos asn1crypto.x509.Certificate (firmante, inter, reponder, inter) (sin raices)
                        crls=None,                  # CRLs si se tuviesen (de momento queda None hardcodeado)
                    )
                    logger.info("Contexto de validación en DSS añadido.")

                    # TST para perfil A
                    if DSS_TIMESTAMPER:
                        logger.info("Añadiendo TST en '/DocTimeStamp'...")
                        DSS_TIMESTAMPER.timestamp_pdf(
                            pdf_out=firmado,    # 'IncrementalPdfFileWriter'
                            output=REV,         # '_io.BytesIO'
                            md_algorithm=DSS_TIMESTAMPER_HASH,
                        )

                        # parece salvaje pero para cada sesión de firma la última firma hecha siempre es el TST de
                        # /DocTimeStamp. Y dado que este TST no es un CMS anidado como contrafirma, se retornará tal
                        # cual lo almacena pyhanko en el PDF (con cero padding al final como en el CMS del firmante).
                        TST_DSS = PdfFileReader(REV).embedded_timestamp_signatures[-1].pkcs7_content

                        logger.info("Perfil 'Archival (A)' completo (TST incremental en /DocTimeStamp).")
                        PERFIL_FIRMA_INDIVIDUAL.append('A')

                    else:
                        firmado.write(REV)

                        # 'REV' se entiende como la revisión final del PDF, lo que se escribe a archivo final.
                        # si hay TST en DSS, el método ".timestamp_pdf()" internamente hace la escritura a REV para
                        # incluír el TST (CMS de la TSA) en /DocTimeStamp.
                        # Si no; se escribe a REV desde el método ".write()" de los 'IncrementalPdfFileWriter' desde
                        # la variable 'firmado' (que es "la versión más completa" del pdf que no usa TST en DSS)
                        # Cualquiera que sea el caso, REV se manejará como '_io.BytesIO' para escribir en el, leer el
                        # historial de firmas antes de cerrar y pasarlo a bytes para escribirlo en archivo final.

                    # Perfil y conteo visual de firmas.
                    logger.info("Firma 'PAdES-B-%s' efectuada correctamente.", ''.join(PERFIL_FIRMA_INDIVIDUAL))
                    
                    firmas_totales = pdf_utils.leer_firmas_pdf(pdf_input=REV)
                    if firmas_totales:
                        logger.info("========== HISTORIAL DE FIRMAS ==========")
                        for n, j in enumerate(iterable=firmas_totales, start=1):
                            logger.info("%s. %s", n, j)
                        logger.info("========== HISTORIAL DE FIRMAS ==========")

                    # Guardado de archivos de cada iteración.
                    general.guardar_archivos(f'{DIR_SESION_FIRMA}/(complemento) archivos separados', 'p7s', **{f"{PDF.stem}_CMS":cms_bytes})
                    if TST_CMS:
                        general.guardar_archivos(f'{DIR_SESION_FIRMA}/(complemento) archivos separados', 'der', **{f"{PDF.stem}_TST-Firmante":TST_CMS})
                    if TST_DSS:
                        general.guardar_archivos(f'{DIR_SESION_FIRMA}/(complemento) archivos separados', 'der', **{f"{PDF.stem}_TST-PDF":TST_DSS})

                    logger.info("Cerrando PDF: '%s'", PDF.name)
                    with open(NOMBRE_PDF_FIRMADO, 'wb') as f_out:
                        f_out.write(REV.getvalue())

    # Wrap up: almacenado de archivos relevantes para calidad de vida.
    if Path(f'{DIR_SESION_FIRMA}/(complemento) archivos separados').is_dir():
        with open(f'{DIR_SESION_FIRMA}/(complemento) archivos separados/0disclaimer.txt', 'w') as f:
            f.write(config.MENSAJES_MISC['disclaimer_firmas_separadas'])

    if FIRMANTE_CA_CHAIN:
        general.guardar_archivos(f'{DIR_SESION_FIRMA}/firmante_info', 'txt', resumen_cadena=pki.leer_ca_chain_simple(chain_path=FIRMANTE_CA_CHAIN).encode('utf-8'))
        general.guardar_archivos(
            f'{DIR_SESION_FIRMA}/firmante_info', 'pem',
            firmante_x509=pem.armor(der_bytes=FIRMANTE.signer.signing_cert.dump(), type_name="CERTIFICATE"),
            firmante_cadena=pki.hacer_cadena_pem(chain_path=FIRMANTE_CA_CHAIN, elementos="no_subject")
        )

    if OCSP_INFO:
        general.guardar_archivos(f'{DIR_SESION_FIRMA}/ocsp_info', 'der', status_ocsp=ocsp_raw_response)
        general.guardar_archivos(f'{DIR_SESION_FIRMA}/ocsp_info', 'txt', status_ocsp_textual=ocsp.leer_ocsp_response(der_bytes=ocsp_raw_response).encode('utf-8'))
        general.guardar_archivos(f'{DIR_SESION_FIRMA}/ocsp_info', 'pem', responder_x509=pem.armor(der_bytes=responder_x509.dump(), type_name="CERTIFICATE"))
        if OCSP_CA_CHAIN:
            general.guardar_archivos(f'{DIR_SESION_FIRMA}/ocsp_info', 'txt', resumen_cadena=pki.leer_ca_chain_simple(chain_path=OCSP_CA_CHAIN).encode('utf-8'))
            general.guardar_archivos(f'{DIR_SESION_FIRMA}/ocsp_info', 'pem', responder_cadena=pki.hacer_cadena_pem(chain_path=OCSP_CA_CHAIN, elementos="no_subject"))
            # no es necesario usar .decode() para las cadenas puesto que el resultado a escribir ya son ascii bytes en estructura PEM

    # Resumen de sesión.
    end_time = f"{(perf_counter() - ini_time):.3f}"
    print()
    print(f"[{Fore.LIGHTGREEN_EX}OK{Fore.WHITE}] Sesión de firma finalizada.")
    print(f"   • Duración: {end_time}s")
    print(f"   • Total de Firmas: {len(PDFs)}")
    print(f"   • Fecha: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")} (UTC)")
    print(f"   • Ruta Archivos: '{Path(DIR_SESION_FIRMA).absolute()}'")

    return True

def hacer_firma():
    logger.info("Usando configuración por defecto.")
    config.load_global()
    FIRMANTE_INDIVIDUAL = config.load_current_user()

    # 1. Evaluar que el material a firmar sea viable antes de cualquier otra cosa, evidentemente (¬_¬").
    pdf_ruta_base = Path(config.GLOBAL_CONFIG['pdf_ruta_base'])
    lista_pdfs = list(pdf_ruta_base.glob(pattern="*.pdf"))
    if not lista_pdfs:
        logger.warning("No hay material para firmar en: '%s' (,,¬﹏¬,,)!", Path(config.GLOBAL_CONFIG['pdf_ruta_base']).absolute())
        logger.warning("Añada uno o más documentos .pdf y empiece a firmar!")
        return False

    # 1.5 Pre-fima
    lista_pdfs = integridad_pdfs.pre_firma(lista_pdfs=lista_pdfs)
    if not lista_pdfs:
        return False

    # 2. Si el material a firmar es viable (independientemente de cuanto sea) se instancia el contexto
    # PKI en el que operará el firmante, y se definirá el contexto/configuración de firma del firmante.
    pki_ctx = pki.get_validation_context(
        trust_roots=config.GLOBAL_CONFIG['PKI']['trust_roots'],
        intermediate_cas=config.GLOBAL_CONFIG['PKI']['intermediate_cas'],
    )
    firmante_ctx = contexto(
        firmante_input=FIRMANTE_INDIVIDUAL,
        pki_ctx=pki_ctx
    )
    if not firmante_ctx:
        return False

    # 3. Si existe firmante instanciado en su contexto PKI y con contexto de firma; se inicia el
    # procedimiento de firma real sobre el material.
    firma(pdfs=lista_pdfs, firmante_ctx=firmante_ctx)

    # TODO:
    # Se pueden firmar documentos ya firmandos, pero no se pueden solapar los 'field_name' de sigmeta.
    # En caso de que un firmante repita su firma sobre un PDF deben gestionarse los 'field_name' de
    # todos los firmantes repetidos antes de firmar efectivamente.
    # ¿Es un caso de uso común la firma repetida? ¿re-firmar un PDF que uno mismo ya había firmado?

    # TODO:
    # Sería ideal hacer un sistema dinámico de nombrado de PDFs según su cantidad de firmas acumuladas
    # por sesión de firma. En lugar de meter el texto estático "_FIRMADO", se podría agregar algo como:
    # "_revN" donde N sea un número natural positivo icremental según las sesiones de firma totales.

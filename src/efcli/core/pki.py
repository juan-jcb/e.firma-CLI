import logging, asyncio
from binascii import unhexlify

from asn1crypto import pem, x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives.serialization import Encoding

from pyhanko_certvalidator import CertificateValidator, ValidationContext, ValidationPath
from pyhanko_certvalidator.errors import ExpiredError

logger = logging.getLogger(__name__)

def get_validation_context(trust_roots: str, intermediate_cas: str) -> ValidationContext:
    """
    Carga los certificados x509 de las CAs de una determinada PKI para establecer
    el contexto de validación necesario para operar con sus certificados.
    
    pyhanko usa ValidationContext para reconstruír las cadenas de confianza
    'hacia atrás' desde el certificado de entidad final, seleccionando de
    los pools disponibles los certificados que encajan (por DN y verificación
    de firma) hasta llegar a alguno de los trust roots disponibles en un
    ValidationContext; si hay múltiples caminos posibles, intenta construir
    uno válido.

    Lo que no hace automáticamente es distinguir si un certificado debe
    pertenecer a trust_roots o a other_certs; esa separación es semántica
    y responsabilidad de cómo se gestiona el contenido de dichas variables;
    los de trust_roots se aceptan como ancla de confianza implicita sin
    verificar quién los emitió, los de other_certs deben estar encadenados
    lógicamente en su contexto PKI.

    Es por tanto, en caso de que se gestione una PKI privada y ya se tenga
    de antemano un bundle de certificados raíz y de certificados de CA
    intermedias separados semanticamente, cada uno de estos recopilados
    se pasaría como variable a los parametros trust_roots y other_certs
    según corresponda y a partir de ello cada vez que se necesite reconstuír
    una cadena de confianza completa se ingresa un x509 de entidad final para
    la construcción del objeto ValidationPath (siempre y cuando este x509
    de entidad final pertenezca al contexto de esta PKI y haya sido emitido
    por cualquiera de las CA en other_certs)

    ValidationContext puede tener estado interno relacionado con caché de
    revocación, por lo que la reutilización del contexto entre validaciones
    puede resultar problematica (concurrencia, estado corrupto entre validaciones),
    la opción de uso segura es instanciarlo para cada validación de certificado
    individual. Por ejemplo:

        # Se instancia el contexto estáticamente 1 vez
        context = ValidationContext(
            trust_roots=root_ca_bundle,
            other_certs=intermediate_ca_bundle,
        )

        # Por cada certificado de entidad final a validar se instancia el
        # validador derivado del contexto:
        for end_entity_cert in end_entity_certs:
            validator = CertificateValidator(end_entity_cert, validation_context=context)
            path = await validator.async_validate_usage({"digital_signature"})
    
    :param trust_roots:
        `str` de ruta tipo OS al archivo de CAs raíz en las que se
        confiará implícitamente.
    
    :param intermediate_cas:
        `str` de ruta tipo OS al archivo de CAs intermedias en las
        que se confiará implícitamente, DEBE estár relacionada
        criptográfica y jerarquicamente a las CA raíz de trust_roots.

    :return:
        Objeto `ValidationContext` de la PKI.
    """

    # Mientras sean rutas constantes y los bundles PEM estén semánticamente separados no hay problema
    with open(trust_roots, "rb") as f:
        roots_bundle = f.read()

    with open(intermediate_cas, "rb") as f:
        inters_bundle = f.read()

    root_x509certs = crypto_x509.load_pem_x509_certificates(roots_bundle)
    inter_x509certs = crypto_x509.load_pem_x509_certificates(inters_bundle)

    bx_trust_anchors = [asn1_x509.Certificate.load(i.public_bytes(encoding=Encoding.DER)) for i in root_x509certs]
    sat_inter_cas = [asn1_x509.Certificate.load(i.public_bytes(encoding=Encoding.DER)) for i in inter_x509certs]

    # Contexto de validación.
    pki_ctx = ValidationContext(
        trust_roots=bx_trust_anchors,       # Lista de CA(s) raíz en las que se confíará implicitamente (lista de certs x509 de asn1crypto)
        other_certs=sat_inter_cas,          # Lista de CA(s) intermedias emitidas por las raíz (lista de certs x509 de asn1crypto)
        revocation_mode="soft-fail",        # "hard-fail" falla si no hay validación OCSP/CRL (soft en caso contrario) "require" si se quiere CRL/OCSP obligatorio
        allow_fetching=False,               # "True" gestiona fetch automáticamente de CRL/OCSP en línea
    )

    return pki_ctx

def get_ca_chain(cert: asn1_x509.Certificate, pki_ctx: ValidationContext, tipo="firmante") -> ValidationPath | None:
    """
    Obtén la cadena de confianza completa en base a un x509.
    
    :param cert:
        Objeto `asn1crypto.x509.Certificate` del cual se obtendrá su
        cadena de confianza completa.

    :param tipo:
        `str` para definir el "tipo de entidad" según su `key usage` y
        `extended key usage` ej: "firmante" para FIEL o SELLO (digital_signature),
        "ocsp_responder" para servidores OCSP.

    :param pki_ctx:
        Objeto `ValidationContext` que define contexto de la PKI bajo la
        que se reconstruirá la cadena de confianza de `cert`.

    :return:
        Objeto `ValidationPath` (iterable e indexable) con la cadena de
        confianza completa en estructura predecible: [root, inter, ..., user]
        ordenado desde el trust anchor (raíz) hasta el certificado sujeto.
    """

    try:
        # certs de firmantes en general (FIEL o SELLO)
        if tipo == "firmante":
            chain_path = asyncio.run(
                CertificateValidator(
                    end_entity_cert=cert,
                    validation_context=pki_ctx,
                ).async_validate_usage({"digital_signature"})
            )

        # certs de servidores OCSP
        elif tipo == "ocsp_responder":
            chain_path = asyncio.run(
                CertificateValidator(
                    end_entity_cert=cert,
                    validation_context=pki_ctx,
                ).async_validate_usage(key_usage={}, extended_key_usage={"ocsp_signing"})
            )

    # pyhanko_certvalidator.errors.ExpiredError: The path could not be validated because the end-entity certificate expired 2026-04-23 17:13:16Z
    except ExpiredError as e:
        logger.error("Certificado X.509 EXPIRADO: %s", e.expired_dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
        return None
    except Exception as e:
        logger.error(e)
        return None
    else:
        return chain_path

def es_cert_banxico(cert: asn1_x509.Certificate) -> bool:
    """
    Determina si un x509 pertenece a la PKI de Banxico.
    
    Esta función utiliza los bundles de PKI desde 'assets/' por lo que no depende de
    que exista un entorno XDG previo.
    """
    from efcli.config import PKI_ASSETS
    TRUST_ROOTS = PKI_ASSETS[0]
    INTERMEDIATE_CAS = PKI_ASSETS[1]

    pki_ctx = get_validation_context(trust_roots=TRUST_ROOTS, intermediate_cas=INTERMEDIATE_CAS)

    # TODO: no me termina de convencer esta estructura, de momento asumimos que hay solo 2 tipos de end-entities, firmantes y responders
    try:
        chain = get_ca_chain(cert=cert, pki_ctx=pki_ctx)
    except Exception:
        chain = get_ca_chain(cert=cert, pki_ctx=pki_ctx, tipo="ocsp_responder")
    
    if not chain:
        return False
    return True

def hacer_cadena_pem(chain_path: ValidationPath, elementos: str = "full_chain") -> bytes:
    """
    Función simple para transformar un objeto `ValidationPath` a una secuencia
    de ascii bytes en estructura PEM. Útil para castear a `str` e imprimir o
    para escribir `bytes` directamente en archivo.

    :param chain_path:
        Objeto `ValidationPath` con la cadena completa que se serializará a PEM.
    
    :param elementos:
        `str` para indicar que elementos excluír (o no) en la secuencia resultante.
        Para excluír la end-entity: "no_subject". Por defecto: "full_chain".

    :return:
        `bytes` ascii de la cadena en PEM estilo bundle.
    """

    if elementos == "no_subject":
        longitud_cadena = range(0, len(chain_path) -1) # el end-entity es el último elemento por lo que se excluye
    elif elementos == "full_chain":
        longitud_cadena = range(0, len(chain_path))

    cert = b''
    for i in longitud_cadena:
        cert += pem.armor(
            der_bytes=chain_path[i].dump(),
            type_name="CERTIFICATE"
        )
    return cert

def leer_ca_chain_simple(chain_path: ValidationPath) -> str:
    """
    Función simple para leer y almacenar en variable `str` los contenidos
    más relevantes de una cadena de confianza completa en orden comprensible.
    """
    longitud_cadena = range(0, len(chain_path))
    entidades = {
        0: "RAIZ DE CONFIANZA",
        1: "AUTORIDAD INTERMEDIA",
        2: "ENTIDAD FINAL"
    }
    
    resumen = "========== Cadena de Confianza ==========\n\n"
    #print("========== Cadena de Confianza ==========\n")
    for i in longitud_cadena:        
        serial_asn1 = chain_path[i]['tbs_certificate']['serial_number'].native
        serial_hex  = format(serial_asn1, 'x')
        serial_sat  = unhexlify(serial_hex).decode('ascii')
        vigente_desde = f"{chain_path[i].not_valid_before.strftime("%Y-%m-%dT%H:%M:%SZ")} (UTC)"
        vigente_hasta = f"{chain_path[i].not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ")} (UTC)"
        fingerprint_sha256 = chain_path[i].sha256_fingerprint
        #fingerprint_sha256 = ''.join([j for j in i.sha256_fingerprint])

        # Si serial_hex es impar se agrega un "0" de padding al inicio para operar numero par (calidad de vida).
        if len(serial_hex) % 2:
            serial_hex = "0" + serial_hex
        serial_hex_colon = ':'.join(serial_hex[k:k+2] for k in range(0, len(serial_hex), 2))

        # Se define el tipo de entidad en base al iterador actual en la cadena de confianza.
        # Ya que range() determina dinámicamente la longitud de la cadena, y dado su ordenamiento
        # en ValidationPath, podemos asumir que 0 siempre es la raíz y -1 es la entidad final,
        # de tal modo que cualquiera otro valor será una CA intermedia.
        if i == longitud_cadena[0]:
            tipo_entidad = entidades[0]
        elif i == longitud_cadena[-1]:
            tipo_entidad = entidades[2]
        else:
            tipo_entidad = entidades[1]

        subject_cn = ''
        subject_ui = ''
        subject_sn = ''
        for rdn in chain_path[i]['tbs_certificate']["subject"].chosen:
            for attr in rdn:
                if attr["type"].native == "common_name":
                    subject_cn = attr["value"].native
                if attr["type"].native == "unique_identifier":
                    subject_ui = f"({attr["value"].native})"
                if attr["type"].native == "serial_number":
                    subject_sn = f"({attr["value"].native})"

        issuer_cn = ''
        issuer_ou = ''
        for rdn in chain_path[i]['tbs_certificate']["issuer"].chosen:
            for attr in rdn:
                if attr["type"].native == "common_name":
                    issuer_cn = attr["value"].native
                if attr["type"].native == "organizational_unit_name":
                    issuer_ou = f"({attr["value"].native})"

        resumen += f"""CERTIFICADO X.509:    {tipo_entidad}
Sujeto:               {subject_cn} {subject_sn} {subject_ui}
Emisor:               {issuer_cn}
Serial SAT:           {serial_sat}
Serial X.509:         {serial_hex_colon}
Fingerprint SHA-256:  {fingerprint_sha256}
Vigencia:             Desde: {vigente_desde}
                      Hasta: {vigente_hasta}\n
"""
    resumen += "========== Cadena de Confianza ==========\n"

        #print(f'CERTIFICADO X.509:    {tipo_entidad}')
        #print(f'Sujeto:               {subject_cn} {subject_sn} {subject_ui}')
        #print(f'Emisor:               {issuer_cn}')
        #print(f'Serial SAT:           {serial_sat}')
        #print(f'Serial X.509:         {serial_hex_colon}')
        ##print(f'Serial ASN.1 INTEGER: {serial_asn1}')
        #print(f'Fingerprint SHA-256:  {fingerprint_sha256}')
        #print(f'Vigencia:             Desde: {vigente_desde}')
        #print(f'                      Hasta: {vigente_hasta}\n')
        ##print(f'X.509 SUBJECT:        {j.subject.human_friendly}')
        ##print(f'X.509 ISSUER:         {j.issuer.human_friendly}')
    #print(f"========== Cadena de Confianza ==========")
    
    # for j in i['tbs_certificate']["subject"].chosen:
    #     print(j)
    #     for k in j:
    #         print(k['type'].native)

    return resumen

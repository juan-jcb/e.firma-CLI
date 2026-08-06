from efcli.config import APP

# Siempre y cuando se respete el nombre de las claves respecto a su proposito, hardcodeado debe funcionar.

#mensajes_dummy = {
#    'directorio_firmas': """1. Directorio de firmas.""",
#    'usuario_local': """2. Usuario local.""",
#    'archivos_efirma': """3. Firma electrónica.""",
#    'metadatos_firma': """4. Metadatos de su firma.""",
#}

mensajes_init = {
    'directorio_firmas': """1. Directorio de firmas.

e.firma CLI definirá en su $HOME un directorio dedicado a las operaciones involucradas con firmas digitales. Este directorio está
diseñado para que ahí mueva los archivos .pdf que desea firmar (puede ser 1 pdf o más, ya que la lógica para firmar es la misma
sin importar si la firma es por archivo individual o por lote).

Será en ese directorio cuyo nombre usted indice que se generarán los resultados de cada firma en un forma de un subdirectorio nuevo
fácil de indentificar creado en cada instancia o sesión de firma.
""",

    'usuario_local': """2. Usuario local.

e.firma CLI utiliza perfiles de usuario locales que recopilan los datos más relevantes para efectuar una firma digital.

A continuación se desglosarán los campos necesarios para crear un perfil de usuario completo y establecer la configuración global del
programa. Para comenzar a utilizar efcli se requiere unicamente de 1 usuario, el cual si posteriormente lo desea podrá editar, crear
nuevos usuarios, borrar ya existentes o consultar configuraciones mediante el submodulo 'efcli user'.
""",

    'archivos_efirma': f"""3. Firma electrónica.

Para firmar documentos se requiere de los archivos incluidos en su e.firma:

    - Clave privada (archivo .key)
    - Certificado X.509 (archivo .cer)

Este programa realizará *1 copia* de cada archivo y las almacenará localmente en la ruta XDG estándar (XDG_DATA_HOME) del usuario actual
en su sistema operativo, y hará lo mismo para cada usuario nuevo creado, por ejemplo:

    '/home/mi_usuario/.config/{APP}/usuario_local/usuario_local.key'
    '/home/mi_usuario/.config/{APP}/usuario_local/usuario_local.crt'
""",

    'metadatos_firma': """4. Metadatos de su firma.

Cada vez que usted efectua una firma PAdES, independientemente del perfil utilizado (B, L, T, A) el PDF resultante incluirá metadatos
de su firma visibles en cualquier validador de firmas digitales (como Adobe Acrobat Reader), esto para facilitar la distinción visual
por ejemplo en casos donde 1 mismo PDF posee multiples firmas.

Los metadatos de firma son:

    1. Identificador de la firma: Cualquier cadena de texto dificil de repetir (recomiendo CURP ya que es relativamente unico).
    2. Nombre del firmante: El nombre de la persona que realiza la firma (en el 99% de los casos es el dueño de la e.firma).
    3. Razón de firma: Justificación corta de cómo o por qué se firma (ej: "Firmado personal con mi e.firma").
    4. Lugar de firma: Ubicación generalizada de la firma (ej: "México", "Puebla", "Administración", "Sistemas").
    5. Contacto del firmante: Comunmente el correo del firmante.

Matiz adicional.

Si usted duda sobre utilizar datos personales en los campos de metadatos de su firma, esto no supone una exposición innecesaria
de información puesto que el propio certificado X.509 de su e.firma ya incluye datos relevantes de su dueño, especificamente en
el 'Subject:' y sus campos:

    - CN=, name=, O=            (ya contiene su nombre completo)
    - serialNumber=             (ya contiene su CURP)
    - x500UniqueIdentifier=     (ya contiene su RFC)
    - emailAddress=             (ya contiene el correo que uso en el trámite de emisión)

Cualquier firma PAdES (sin importar el perfil) incluye el certificado x509 del firmante (además de los metadatos) dentro del
PDF resultante, por lo que, aunque usted decida no los incluir metadatos explicitamente, si firma mediante PAdES cualquiera que
valide dicha firma podrá leer los campos antes mencionados desde su certificado para saber exactamente de quién proviene.

Puede llenar los campos o dejarlos en blanco (ENTER) a criterio, de igual forma esta herramienta le permitirá cambiarlos más
adelante si así lo desea.
""",

    'pefiles_firma': """5. Preferencias para perfil de firma.

Los perfiles (o niveles) de firma definidos en ETSI EN 319 142-1 especifican qué elementos criptográficos y de validación debe
incorporar una firma PAdES incrustada en un PDF. Definen los requisitos de presencia y cardinalidad sobre los campos de firma,
atributos y servicios para cuatro niveles de firma baseline:

    Basic (B), Long-Term (L), Timestamp (T), Archival (A)

Los cuales suelen seguir la siguiente estructura progresiva: B -> L -> LT -> LTA
    
El perfil determina directamente hasta cuándo y bajo qué condiciones un validador puede comprobar la validez de la firma: cuanto
mayor es el nivel, mayor es la resistencia frente a la expiración/revocación de certificados y frente a la degradación criptográfica
con el paso del tiempo.

e.firma-CLI le permite ejecutar los 4 perfiles de firma, dandole al firmante la libertad de elegir exactamente qué perfil en sus
firmas: Solo B, ascender de B a L, añadir T, añadir A, o cualquiera de sus posibles combinaciones. No obstante, con el fin de
reducir la carga de configuración necesaria para cada firma es que esta herramienta define "preferencias de perfil de firma", y
las almacena como valor constante en el mismo archivo de usuario local donde se encuentran las rutas de su clave/certificado y
así simplificar la elección del perfil para culquier firma PAdES posterior.

A continuación se le presentarán una serie de preguntas de respuesta SI/NO, en las cuales solo tiene que aceptar o negar según lo
que prefiera para establecer los valores. De igual modo que en los metadatos de firma, podrá modificar sus elecciones más adelante
si así lo desea.
""",

    'preferencias_uso': """6. Preferencias adicionales sobre el uso del programa.

Se han concluído las configuraciones necesarias en lo que refiere al contexto PAdES, sin embargo existen un par de opciones
adicionales sobre el uso de este programa que usted puede configurar.

1. Uso o no uso de confirmación automática sobre la reparación de PDFs defectuosos.
    
Es más común de lo que parece que no todos los documentos PDF sean inicialmente procesables por la lógica de firmas de este programa
y las razones pueden ser diversas: software de edicion, escaneres de multifuncionales o de aplicación movil que no implementen
correctamente el estandar PDF, corrupción accidental por interrupción de un flujo de descarga/transferencia, entre un largo etcetera.

Para garantizar que sus PDFs puedan ser firmados correctamente con e.firma CLI, antes de la sesión de firma real con tus claves
privadas se realiza siempre un "simulacro de firma" con todos los documentos que usted proponga para evaluar si son correctamente
procesables, y finalmente firmables. Es durante este simulacro donde se le puede presentar a usted un prompt de confirmación por cada
incidencia de PDF defectuoso, en el cual deberá decidir si quiere repararlo o no para proseguir con su firma real.

La reparación de PDFs es parte fundamental de la lógica del programa, y consiste en la *creación un archivo PDF nuevo* por cada PDF
reparado. Los PDFs reparados son *visualmente identicos* a los originales por lo que el contenido de su PDF original no se pierde.
No obstante el prompt que esta herramienta utiliza para hacerle saber a usted que se ha encontrado con un PDF no procesable requiere
por lógica de una interacción explicita con el usuario para cada PDF normalizado/reparado, y es justo ahí donde repercute esta
preferencia de uso: en el prompt de confirmación sobre la reparación de un PDF defectuoso. Es decir, el prompt puede no ser incomodo
para pocos PDFs reparados en una misma sesión de firma, pero cuando hablamos de firma en lote +100 PDF; confirmar manualmente la
reparación de cada uno puede tornarse incomodo muy rapidamente, y esta preferencia de uso se enfoca en dichos casos.

Si utiliza autoconfirmación de reparación de PDFs da igual si firma uno o 100,000 de PDFs; la reparación de cada PDF defectuoso
encontrado se aplicará en automático sin necesidad de una confirmación explicita por su parte.

2. Preservación en disco sobre los PDFs normalizados posterior a cada sesión de firma.

Este punto es consencuencia directa del anterior.

Como ya se ha hecho mención, la reparación de PDFs crea un archivo nuevo por cada reparación, y esta preferencia de uso aborda esa
situación. La preservación en disco de PDFs normalizados instruye al programa sobre si debe de eliminar o preservar en disco todos
aquellos *PDFs reparados* que hayan sido creados durante el simulacro. 

Decida lo que decida sus PDFs originales y los PDFs firmados resultantes de las sesiones de firma nunca se tocan, esta preferencia
simplemente se define si usted desea preservar o los PDFs reparados o no.
""",

    'bienvenida_corta': """Bienvenido a e.firma CLI!

Una herramienta de terminal que permite operar de manera simplificada en el contexto de la PKI del Banco de México y el SAT, y
principalmente enfocada a las operaciones de firma digital que se pueden realizar con las claves privadas (E.FIRMA, SELLO) de
algoritmo RSA, proporcionadas por diferentes entidades como el SAT en su respectivo trámite para emisión de e.firma.

'e.firma CLI' le otorga al poseedor de una e.firma la capacidad de operar su e.firma, realmente como una firma electrónica para
firmar sus propios documentos de manera gratuita bajo el esquema PAdES: \"PDF Advanced Electronic Signatures\" en todos sus
perfiles de firma:

    - 'Basic (B)'
    - 'Long-Term (L)'
    - 'Timestamp (T)'
    - 'Archival (A)'

INTRODUCCIÓN AL USO.

Para facilitar la interacción con ésta herrienta en su uso cotidiano se emplean configuraciones de usuario las cuales necesita
completar con algunos datos relevantes.

Se le pide que lea atentamente las indicaciones que a continuación se le presentan para que tenga una introducción adecuada sobre
el uso de esta herramienta. Sientase libre de cancelar en cualquier momento este procedimiento utilizando CTRL+C y reiniciar con
el mismo comando 'efcli init'
""",
    
    'bienvenida_larga': """Bienvenido a e.firma CLI!

Una herramienta de terminal que permite operar de manera simplificada en el contexto de la PKI del
Banco de México y el SAT.

Principalmente enfocada a las operaciones de firma digital que se pueden realizar con las claves
privadas RSA que son proporcionadas por diferentes entidades como el SAT en su respectivo trámite
para emisión de e.firma.

'e.firma CLI' le otorga al poseedor de una e.firma la capacidad de operar su e.firma, realmente como
una firma electrónica para firmar sus propios documentos de manera gratuita bajo el esquema PAdES:
\"PDF Advanced Electronic Signatures\" en todos sus perfiles de firma:

    - 'Basic (B)'
    - 'Long-Term (L)'
    - 'Timestamp (T)'
    - 'Archival (A)'

SOBRE EL PROPÓSITO.

Si bien las firmas digitales 'per se' tienen un uso más extendido en la comunicación segura entre
sistemas (sin intervención humana), el hecho de que Banxico haya decido operar este esquema de
entidades criptográficas bajo el estándar ASN.1/X.509, permite ampliar las capacidades de dichas
firmas hacia ámbitos con una repercución, por así decirlo \"más tangible\" y notoria para los dueños
de estos artefactos; como lo es la firma estandarizada de documentos PDF bajo el esquema PAdES (en
la cual se centra la presente herramienta) y que es perfectamente compatible con cualquier PKI,
sea pública o privada, como en el caso de la PKI privada de Banxico y sus autoridades de certificación
intermedias como el SAT.

Bajo este contexto es que se desarrolla 'e.firma CLI'; con el fin de aprovechar la criptografía
subyacente de estos artefactos (ya existentes para cualquiera que haya realizado su trámite de emisión
de e.firma) para realizar firmas digitales, y por ende las caracteristicas de integridad, autenticidad
y no redudio que la criptografía asimétrica le otorga a las firmas efectuadas (a mi jucio muy superior
a las firmas autógrafas, siempre y cuando se comprenda cómo operan con estos elementos), así como el
ecosistema de validación de entidades denotado por los certificados X.509 que acompañan a las claves
y pertenecen al contexto jerarquico de la PKI del Banco de México.

De tal modo que realmente se haga valer la terminología de \"firma electrónica\" que la e.firma
publicita, y que éstos artefactos criptográficos tengan un uso real y asequible para sus poseedores,
más allá de ser un factor de autenticación generico utilizado por SAT e IMSS en sus páginas web para
permitir el acceso a perfiles de usuario ¯\\_(ツ)_/¯, y si acaso realizar firmas puntuales, pero siempre
bajo contexto cerrado (principalmente facturas), en pocas palabras, sin control real del usuario sobre
el material que ya posee y los alcances potenciales que este puede tener más allá de la criptográfia;
gracias a la homologación de "firma equivalente a la autógrafa", fundamentada en los articulos 1803
fracción I del Código Civil Federal, y de los articulos: 89 párrafo 3 y 97 párrafo 2 fracciones I, II,
III y IV del Código de Comercio.

En terminos prácticos se puede entender a la e.firma como un mecanismo de identidad fundamentado en
criptografía, y que adquiere el caracter de "identidad pública en contexto nacional" en el momento
que una de estas claves criptográficas es vinculada a un certificado X.509 emitido por una entidad
de confianza; siendo esta la entidad raíz en una PKI (el Banco de México), y de la que se extienden
las entidades certificadoras intermedias (como el SAT) de la cual emiten los certificados finales del
poseedor (los contribuyentes).

Es por tanto que la existencia de una determinada e.firma 'avala la existencia' de un determinado
contribuyente dado el proceso de autenticación (el trámite) que se realiza personalmente frente a la
entidad certificadora de confianza (el SAT), de tal modo que cualquier firma digital efecutada por una
clave privada que esté asociada a un certificado x509 perteneciente a la PKI del banco de méxico, se
asume como: 'de X contribuyente', y por ende como: 'de X Ciudadano Méxicano con papeles en regla' ya
que la entidad de confianza los corroboró *previo* a crear las claves y emitir los certificados (ademas
claro ¯\\_(ツ)_/¯, de aprovechar el interludio del proceso para recolectar datos biometricos, que nada
tienen que ver con la naturaleza de éstos artefactos criptográficos y su operación real)

MATIZ OPERATIVO.

e.firma CLI permite obtener el perfil de firma más alto para un pdf firmado según PAdES (PAdES-LTA)
el cual en sus perfiles 'T' y 'A' hacen uso de sellos de tiempo 'TST' (RFC 3161).

No obstante es necesario señalar que la secretaría de economia decidió terciarizar las funciones de la
PKI de Banxico mediante lo que ellos denominan como Prestador de Servicios de Certificación (PSC);
empresas de terceros que forman parte operativa en la PKI de Banxico, avalandolos tanto como CA intermedia
para emisión de certificados finales, como TSA dedicadas a la emisión tokens de sellado de tiempo (TST).

Esto tiene implicaciónes juridicas y monetarias más que puramente técnicas y criptográficas.

Las TSAs de PSC son el caso que en mayor o menor medida pueden afectar a los perfiles de firma relacionados
con los sellos de tiempo (Timestamp y Archival), ya que según la NOM-151 un sello de tiempo (denominado
por la NOM como "constancia de certificación" aunque su nombre real es TimeStamp Token o simplemente TST)
que sea emitido por una TSA de un Prestador de Servicios de Certificación es lo que otorga la cualidad
juridica de 'fecha cierta' a una determinada firma digital.

Esta consideración como tal NO afecta a la criptografia subyacente de las claves, los certificados, las
firmas realizadas, y ni siquiera los propios TST; puesto que el TST que puede emiter una TSA pública es
criptográficamente igual de válido al TST emitido por la TSA de un Prestador de Servicios de Certificación.

La unica diferencia real que existe entre las TSAs públicas y las TSAs de PSC es que los PSC son avalados
por la secretaria de economia para ejercer como TSA en este contexto PKI. Además de que un PSC agrega 2
extensiones opcionales extra a sus sellos de tiempo (extensiones opcionales que no alteran la función
principal del TST para fungir como sello de tiempo).

Citando los apendices A.7.1 y A.7.4 de la NOM-151:

    Una de las extensiones a usar en la presente NOM se encuentra especificada en el RFC 5280.
    Las extensiones no se marcarán como críticas.

    Con la finalidad de identificar el inicio de vigencia de la constancia, se incorporan los dos
    siguientes elementos, cuya definición se expresa en la notación ASN.1

        id-nom-ini-time OBJECT IDENTIFIER ::= {2 16 484 101 10 316 20 37 1117}
        NOM151IniTime ::= GeneralizedTime

En términos prácticos el TST de un PSC y el TST de una TSA pública son criptográficamente iguales según
su función principal de sello de tiempo, y solo se diferencian en 2 cosas:

    - El PSC fue avalado por una entidad de gobierno 
    - La TSA del PSC generó un TST con 2 extensiones opcionales en la estructura del sello.

La firma de la TSA sobre el hash enviado en un TSQ (RFC 3161) se aplica de la misma manera para generar
un TST idenpendientemente de si la TSA es pública de internet o si es de un PSC avalado por Economia.
Además claro, de que el acceso a la TSA del PSC para obtener su sellos de tiempo; está debidamente
protegida detras de un muro de pago ¯\\_(ツ)_/¯. Una operación que es técnicamente gratuita en el contexto
actual de internet se restringe por cuestiones administrativas y se aprovecha para cobrar en el proceso.

A mi juicio lo más adecuado sería que Banxico gestione su propia TSA así como gestiona su propia CA raíz,
y que exista 1 sola TSA pública que cualquiera pueda utilizar y sea válida a nivel nacional "( – ⌓ – ).

Como conclusión a esto podemos resumir.

    - e.firma CLI puede firmar con sellos de tiempo T y A de ambos tipos de TSA, sea pública o de PSC

    - Un firma en perfil T y/o A de e.firma CLI es criptográficamente igual de válida tanto si proviene
      de TSA pública como de TSA de PSC.

    - Una firma sin TST de PSC unicamente no posee fecha cierta (que aplica a nivel méxico) y de ello
      se derivan sus respectivas implicaciones juridicas para el documento firmado.

    - Si se utilizan TSTs de PSC evidentemente se tendrá que pagar para obtener acceso a su endpoint
      y posteriormente usarlo en esta herramienta.
"""
}

mensajes_adduser = {
    'directorio_firmas': "",
    'usuario_local': """Añadiendo usuario local.""",
    'archivos_efirma': """Firma electrónica.""",
    'metadatos_firma': """Metadatos de su firma.""",
    'pefiles_firma': """Preferencias sobre el perfil de firma.""",
    'preferencias_uso': """Preferencias adicionales de uso del programa."""
}

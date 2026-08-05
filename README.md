# e.firma CLI

Tu firma electrónica avanzada, tal y como se pretende que se utilice: **para firmar**.

Firma documentos PDF en esquema PAdES-LTV completamente bajo TU control: sin ceder custodia, sin exponer tus claves y/o documentos en infraestructura de terceros.

- Firma PDFs individualmente o en volumen: La misma lógica para firmar uno firmará miles de documentos.
- Elige libremente el perfil de firma que más se ajuste a lo que necesitas: B, BT, BA, BTA, L, LT, LA, LTA, A.
- Totalmente gratuito para perfiles B.
- Gratuito para perfiles L, siempre y cuando el SAT no cierre arbitrariamente sus endpoints OCSP públicos (≧︿≦).
- Gratuito para perfiles T y A según la politica de uso/rate limit de proveedores de sellos de tiempo (RFC 3161) en TSAs públicas de internet.
- De pago en perfiles T y A para sellos de tiempo con fecha cierta por NOM-151. Si en verdad los necesitas contacta tu mismo al PSC! (https://psc.economia.gob.mx/directorio.html) y añade el endpoint de su TSA privada a la configuración del programa.

Se prioriza la custodia de claves y documentos PDF, así como la transparencia criptográfica de la herramienta.

- Claves privadas y archivos PDF nunca salen de tu dispositivo.
- Si el perfil de firma lo requiere, la única comunicación por internet es HTTPS para solicitar estados OCSP a endpoints del SAT y/o sellos de tiempo a endpoints de TSA que tú mismo eliges y configuras.
- La operación de firma digital ocurre 100% en local independientemente del perfil y sus resultados se almacenan localmente.
- Las librerías criptográficas y protocolos utilizados en esta herramienta son públicos y auditables.

Se almacena **en local** una cantidad minima funcional de datos para gestionar un entorno XDG básico y reducir la fricción de uso.

- Se almacenan archivos de configuración y preferencias de uso para el programa y sus usuarios locales.
- Nunca se almacenan contraseñas de claves privadas.
- Nunca se almacenan historiales o registros de firma.
- Los resultados que producen las firmas se almacenan en directorios autocontenidos fáciles de encontrar, navegar y borrar.
- Si ya no necesitas el entorno, borralo completo cuando quieras en 1 solo comando!.

### Requisitos

- Python 3.12 (o superior)
- pip
- venv (para instalación aislada **solo del paquete**, se usa un entorno XDG separado)

### Instalación

```bash
git clone https://github.com/juan-jcb/e.firma-CLI.git
cd e.firma-CLI
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
python3 -m pip install -e . # para desarrollo
deactivate
sudo ln -s ruta/hacia/efcli/.venv/bin/efcli /usr/local/bin/efcli
```

## Contexto operativo.

El Banco de México opera una **PKI privada** bajo el estándar **ASN.1/X.509** que ellos mismos denominan como **Infraestructura IES**.

Esta infraestructura es de la cual deriva la entidad certificadora intermedia del servicio de administración tributaria, y que a su vez es quien emite los certificados de entidad final, es decir; de los contribuyentes, los cuales obtienen su e.firma y sello al realizar el trámite respectivo para e.firma por primera vez en este organismo de gobierno.

    https://www.sat.gob.mx/portal/public/tramites/firma-electronica-avanzada-efirma

Es dentro de éste ecosistema e infraestructura que opera la herramienta **"e.firma CLI"**.

### Consideraciones previas.

Es necesario aclarar desde un inicio de manera explicita que la PKI que opera el banco de méxico **NO está publicamente extendida en el contexto global de internet**. Esto, aunque no es técnicamente un impedimento sí requiere de mención enfatizada, ya que de esta condición de partida es que derivarán configuraciones adicionales que deben considerarse por cualquiera que quiera utilizar esta herramienta en su plenitud.

Los certificados X.509 de las entidades certificadoras raíz de la PKI del banco de méxico **NO se distribuyen entre sistemas de manera automática** (como sí les sucede a las entidades certificadoras raíz publicas en internet, que suelen venir pre-instaladas en navegadores web, almacenes de confianza de sistemas operativos y librerías de programación).

Dicho esto, aunque ambos tipos de entidades certificadoras (privadas/públicas) apliquen los mismos procesos/protocolos/operaciones criptográficas y posean **la misma credibilidad técnica**, no poseen la misma "credibilidad reputacional" (en contexto internet), por lo que la confianza en cada una variará según su origen, y de ello toman forma las acciones requeridas para confiar efectivamente en una determinada entidad.

Por ejemplo:

- Una PKI pública NO requiere configuración de confianza, **posee confianza implicitamente**.
- Una PKI privada SI requiere configuración de confianza, **adquiere confianza explicitamente**.

La PKI del banco de méxico es privada, y por tanto requiere de configuración explicita de confianza. Esto quiere decir literalmente que, para confiar en las entidades certificadoras raíz del banco de méxico y (por confianza transitoria) en cualquier otra entidad certificadora intermedia en su jerarquía PKI (como la del SAT) es necesario **importar manualmente** los certificados X.509 de éstas CA **en cualquier software y/o nodo que vaya a interacturar con artefactos criptográficos relacionados a éste contexto PKI** (como lo son E.FIRMA/SELLO) y cualquier resultado subderivado (firmas digitales con identidad basadas en PKI).

Afortunadamente para ello, banxico expone en su página web oficial un listado con sus prinicipales entidades certificadoras:

    https://www.banxico.org.mx/services/ies-certificates-electronic-s.html

### La confianza explícita y su relación con ésta herramienta.

e.firma CLI es, en su base fundamental, software para realizar firmas digitales, cuya naturaleza y ecosistema operativo contempla la acción de **validación de firma** a la par de **indispensable** como cualquier firma realizada. Es decir, el ciclo de vida de la firma digital no puede cerrarse de manera efectiva unicamente con haber hecho la firma, requiere también **haberse validado**, preferentemente por un tercero que no haya participado en la acción de firma, pero que confie en la misma entidad certificadora raíz a la que pertenece jerarquicamente el firmante.

En nuestro caso esas entidades son las CAs raíz de Banxico, que se configurarán manualmente para confiar en ellas y por ende confiar también en cualquier artefacto perteneciente a su contexto, ergo; las firmas digitales realizadas con ésta herramienta.

Esto se traduce en la práctica tal que: es necesario descargar desde el listado oficial de entidades certificadoras de Banxico los certificados X.509 de las entidades denominas como **Main Registration Agency** para los siguientes números de serie:

- 00000000000000000003
- 00000000000000000004
- 00000000000000000005

E importarlos manualmente en su respectivo ***software de validación de firmas***; por ejemplo **Adobe Acrobat Reader** para poder así validar existosamente cualquier firma realizada, ya sea por e.firma CLI o por otras herramientas disponibles en el mercado (y que operen en el contexto PKI del Banco de México y el SAT).

Adicional: los certificados con números de serie 1 y 2 **no se consideran** puesto que se encuentran vencidos, la entidad raíz 2 siendo el caso más reciente habiendo expirado con fecha: **Jul 20 18:32:51 2026 GMT**, por lo que a efectos prácticos de esta herramientas solo consideraremos los números de serie 3, 4, 5 (6 en un futuro si es que Banxico crease una nueva CA raíz)

## En cuanto al propósito específico de la presente herramienta.

e.firma CLI es una herramienta de linea de comandos escrita en Python diseñada para realizar firmas digitales en documentos PDF implementando el esquema **PAdES-LTV**, y focalizada en el uso de los artefactos **E.FIRMA** y **SELLO** emitidos por la entidad certificadora intermedia del SAT en el contexto PKI del Banco de México.

Esta herramienta tiene como fin rotundo darle al dueño de **su propio material criptográfico** la capacidad **real**, (mayormente) **gratuita** y **sin la tradicional dependencia de terceros comerciales** para efectuar su firma electrónica avanzada tal y como lo que es realmente, en un contexto común conocido y con impacto inmediato notable, es decir: e.firma CLI te permite utilizar **tu clave privada de criptografía asimétrica, para ejecutar operaciones primitivas asimétricas**, principalmente: **la firma digital**, aplicada especificamente a documentos PDF, con los respectivos efectos legales aplicables del marco juridico en el que se fundamentan, véase:

- CODIGO CIVIL FEDERAL MEXICANO: Artículo 1803 fracción 1 "Del consentimiento"
- CODIGO DE COMERCIO MEXICANO: Artículo 89 párrafo 3 "De los mensajes de datos"
- LEY DE FIRMA ELECTRÓNICA AVANZADA: DOF 14-11-2025
- REGLAMENTO DE LA LEY DE FIRMA ELECTRÓNICA AVANZADA: DOF 21-03-2014
- DISPOSICIONES GENERALES DE LA LEY DE FIRMA ELECTRÓNICA AVANZADA: DOF 21-10-2016
- NORMA OFICIAL MEXICANA: NOM-151-SCFI-2016

### ¿Por qué e.firma CLI?

Esta herramienta surge como propuesta de solución para abordar 3 situaciones:

1. **La poca difusion que se le da a las operaciones duras** que puede realizar el material criptográfico, ya existente en manos de miles de contribuyentes, y que pueden utilizar con una finalidad de alto perfil utilitario: la firma de archivos/documentos respaldada por atribución de identidad con implicaciones legales. En lo personal me llama especialmente la atención la disparidad que existe respecto a la cantidad de contenido en internet en relación a éste ecosistema proviniendo principalmente de contadores/abogados en comparación con la de informáticos/criptógrafos.

2. **El poco o casi nulo acceso a alternativas funcionales de bajo coste** para conseguir el fin anteriormente mencionado sin tener que recurrir a proveedores terceros con cuotas de uso considerablemente altas, los cuales fundamentan sus precios y modelo de negocio en "la capa de orquestación y el ritual de firma", no sobre la acción de firma en sí misma, cosa que indirectamente termina restringiendo detrás de muros de pago el acceso a la firma propia y local, ya sea puntual o de alto volumen pero que no requiera una capa de organización y orquestación adicional.

3. **La normalización de la renuncia sobre la custodia del material criptográfico** para que otros servicios la manejen por ti, por ejemplo: el acceso a la emisión de facturas, acceso al buzón tributario o acceso a plataformas de firmas de terceros, todos requieren **la entrega voluntaria del material en plano** a un tercero. Sin mencionar N cantidad de chanchullos informales en los que se te pide hagas entrega de tu material criptográfico bajo la premisa del "confia en mi bro" y a los que lamentablemente se accede por desconocimiento sobre las capacidades e implicaciones posteriores que poseen, otorgan y adquieren este tipo de artefactos.

## En cuanto a la operación principal.

La funcionalidad base de e.firma CLI permite firmar documentos PDF con un perfil de firma máximo **PAdES-B-LTA**, y con total libertad de elección sobre el prefil de firma aplicable en cada sesión de firma.

e.firma CLI te permite ejercer los 4 perfiles de firma de PAdES Baseline dandole al firmante la libertad de elegir el perfil de firma que quiere usar para en cualquiera de sus posibles combinaciones. Y ya que es lo más prudente, de manera resumida se desglosan los perfiles de firma que contempla esta herramienta:

- **B**: Firma con certificado X.509, opcionalmente cadena de confianza de su PKI (e.firma CLI la incluye de todas formas) y hora del reloj del dispositivo del firmante.
- **L**: Firma con certificado X.509, cadena de confianza completa (sin raíz), evidencia OCSP/CRL proveniente de la PKI del firmante y hora del reloj del dispositivo del firmante. Permite corroborar que una determinada firma fue realizada mientras el certificado del firmante era válido, sin depender a posteriori de la infraestructura de la PKI. Es progresión del perfil B (B -> L).
- **T**: Firma con sello de tiempo de TSA incrustado en la propia firma. Es el aspecto que otorga la "fecha cierta" al artefacto de firma situandolo en X momento del tiempo. Es técnicamente una contrafirma hecha por una autoridad de sellado de tiempo TSA. Dicho literalmente: "Una TSA firma la firma del firmante, confiando en la TSA como autoridad imparcial para determinar el tiempo". Es complementario de los perfiles anteriores (ej: BT, LT).
- **A**: Sello de tiempo de TSA sobre 1 PDF con N cantidad de evidencias anteriores. Es el mismo tipo de sello de tiempo (TimeStampToken) pero aplicado sobre el PDF **junto** a cualquier cantidad de evidencias criptográficas pre-existentes (multiples firmas, evidencias de validación, otros TSTs, etc.). Son incrementales. Generalmente ocurren al final de una sesión de firma para sellar todas las evidencias en un determinado momento del tiempo. Le da "fecha cierta" tanto al contenido del PDF junto a cualquier otra evidencia u operación hecha sobre este. Es complementario de los perfiles anteriores (ej: BA, LA, BTA, LTA)

Para su función principal e.firma CLI ya posee una implementación e interfaz mayoritariamente funcional, siempre claro buscando robustecer su operatividad.

### Operaciones adicionales.

e.firma CLI no pretende ser exclusivamente una herramienta para firmar PDFs, aspira a ser una suite completa con una interfaz de uso realtivamente simplifcada para las principales operaciones criptográficas relacionadas con un entorno PKI privado para el firmado de PDFs en esquema PAdES. Esto quiere decir:

- Añadir por separado sellos de tiempo (TST) incrementales a documentos PDF.
- Realizar por separado solucitudes OCSP de certificados X.509, parsear y procesar archivos de respuesta OCSP en local.
- Desglosar el estado actual de un PDF para determinar: si está firmado, cuantas firmas posee, quien firmó, que caracteristicas poseen las firmas y en qué fechas se realizaron.
- Realizar auditoría criptográfica sobre los artefactos generados individualmente en cada operación para determinar explicitamente qué y cómo se está firmando/sellando.

Para tener una referencia de qué operaciones adicionales se pueden hacer actualmente con esta herramienta consultelas post-instalación con: "efcli --help".

## Cierre de la introducción.

Bajo mi juicio y criterio subjetivo las firmas digitales basadas en criptografía son por mucho superiores a las autógrafas tradicionales, y teniendo en cuenta el hecho de que este tipo de artefactos están debidamente regulados por la ley no queda más que extender la difusión sobre las capacidades y caracteristicas que otorga el utilizar éstos elementos con herramientas que prueben ser funcionales y se aproveche adecuadamente de:

- Autenticidad.
- Integridad de los mensajes.
- No repudio criptográfico.
- Atribución de identidad con caracter legal.
- Multiplicador de eficiencia: Mucho más eficiente firmar en digital que a mano.
- Transición paulatina: Reemplazo factible de las firmas fisicas en papel a las digitales por e.firma/sello.

# e.firma CLI

Tu firma electrónica avanzada, tal y como se pretende que se utilice: **para firmar**.

Firma documentos PDF en esquema PAdES-LTV completamente bajo TU control: sin ceder custodia, sin exponer tus claves y/o documentos en infraestructura de terceros.

- Firma PDFs individualmente o en volumen: La misma lógica para firmar uno firmará miles de documentos.
- Total libertad para elegir el perfil de firma que más se ajuste a lo que necesitas: B, BT, BA, BTA, L, LT, LA, LTA, A.
- Totalmente gratuito para perfiles B.
- Gratuito para perfiles L siempre y cuando el SAT no cierre arbitrariamente sus endpoints OCSP públicos (≧︿≦).
- Si verdaderamente necesitas sellos de tiempo RFC 3161 (perfiles T, A) para fecha cierta NOM-151 contacta directamente al PSC y añade el endpoint de su TSA en la configuración del programa: https://psc.economia.gob.mx/directorio.html

Se prioriza la custodia de tu material criptográfico.

- Claves privadas y archivos PDF nunca salen de tu dispositivo.
- No se almacenan contraseñas ni historiales de firma.
- El programa es transparente respecto a qué guarda y dónde lo guarda.
- Borra el entorno completo cuando quieras en 1 solo comando.

### Requisitos

- Python 3.12 (o superior)
- pip
- venv (para instalación aislada **solo del paquete**, se usa un entorno XDG separado)

### Instalación global

```bash
git clone https://github.com/juan-jcb/e.firma-CLI.git
cd e.firma-CLI
python3 -m pip install .
python3 -m pip install -e . # para desarrollo
```

### Instalación aislada

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

La PKI del banco de méxico es privada, y por tanto requiere de configuración explicita de confianza. Esto quiere decir literalmente que, para confiar en las entidades certificadoras raíz del banco de méxico y (por confianza transitoria) en cualquier otra entidad certificadora intermedia en su jerarquía PKI (como la del SAT) es necesario **importar manualmente** los certificados X.509 de éstas CA **en cualquier software y/o nodo que vaya a interacturar con artefactos criptográficos relacionados a éste contexto PKI** (como lo son E.FIRMA y SELLO y cualquier resultado subderivado, como las firmas digitales con identidad basadas en PKI).

Afortunadamente para ello, banxico expone en su página web oficial un listado con sus prinicipales entidades certificadoras:

    https://www.banxico.org.mx/services/ies-certificates-electronic-s.html

### La confianza explícita y su relación con ésta herramienta.

e.firma CLI es, en su base fundamental, software para realizar firmas digitales, cuya naturaleza y ecosistema operativo contempla la acción de **validación de firma** a la par de **indispensable** como cualquier firma realizada. Es decir, el ciclo de vida de la firma digital no puede cerrarse de manera efectiva unicamente con haber hecho la firma, requiere también **haberse validado**, preferentemente por un tercero que no haya participado en la acción de firma, pero que confie en la misma entidad certificadora raíz a la que pertenece jerarquicamente el firmante.

En nuestro caso esas entidades son las CAs raíz de Banxico, que se configurarán manualmente para confiar en ellas (dada su condición de PKI privada) y por ende confiar también en cualquier artefacto perteneciente a su contexto, ergo; las firmas digitales realizadas con ésta herramienta.

Esto se traduce en la práctica tal que: es necesario descargar los certificados X.509 que banxico denomina como **Main Registration Agency**, que poseen los siguientes números de serie:

- 00000000000000000003
- 00000000000000000004
- 00000000000000000005

E importarlos manualmente en su respectivo *software de validación de firmas*, como por ejemplo **Adobe Acrobat Reader** para validar existosamente cualquier firma realizada ya sea por ésta heramienta o por otras disponibles en el mercado (que operen en el contexto PKI de banxico).

Aclaración: los certificados con n° de serie 1 y 2 ya no se consideran puesto que se encuentran vencidos, siendo la entidad raíz 2 el caso más reciente habiendo expirado con fecha: Jul 20 18:32:51 2026 GMT, por lo que a efectos prácticos de esta herramientas solo consideraremos 3, 4 y 5 (6 si es que Banxico crease una CA raíz nueva en el futuro)

## En cuanto al propósito específico de la presente herramienta.

e.firma CLI es una herramienta de linea de comandos escrita en Python diseñada para realizar firmas digitales en documentos PDF implementando el esquema **PAdES-LTV**, y focalizada en el uso de los artefactos **E.FIRMA** y **SELLO** emitidos por la entidad certificadora intermedia del SAT en el contexto PKI del Banco de México.

Esta herramienta tiene como fin rotundo el darle al dueño de **su propio material criptográfico** la capacidad **real**, (mayormente) **gratuita** y **sin la tradicional dependencia de terceros comerciales** de efectuar su firma electrónica tal y como lo que es realmente, en un contexto común y con impacto inmediato notable:

e.firma CLI te permite utilizar **tu clave privada de criptografía asimétrica, para ejecutar operaciones primitivas asimétricas**, principalmente: **la firma digital**, aplicada especificamente a documentos PDF.

### ¿Por qué e.firma CLI?

Esta herramienta surge como propuesta de solución para abordar 3 situaciones:

1. La poca difusion que se le da a **las operaciones duras** que puede ejecutar el material criptográfico ya existente en manos de miles de contribuyentes, y que pueden ser utilizadas con una finalidad de alto perfil utilitario: firma de archivos/documentos respaldada por atribución de identidad con implicaciones legales, véase el fundamento legal:

- CODIGO CIVIL FEDERAL MEXICANO: Artículo 1803 fracción 1 "Del consentimiento"
- CODIGO DE COMERCIO MEXICANO: Artículo 89 párrafo 3 "De los mensajes de datos"
- LEY DE FIRMA ELECTRÓNICA AVANZADA (DOF 14-11-2025)
- REGLAMENTO DE LA LEY DE FIRMA ELECTRÓNICA AVANZADA (DOF 21-03-2014)
- DISPOSICIONES GENERALES DE LA LEY DE FIRMA ELECTRÓNICA AVANZADA (DOF 21-10-2016)
- NORMA Oficial Mexicana NOM-151-SCFI-2016

2. El poco o casi nulo acceso a **alternativas funcionales de bajo coste** para conseguir el fin anteriormente mencionado sin tener que recurrir a proveedores terceros con cuotas de uso considerablemente altas, los cuales fundamentan sus precios y modelo de negocio en "la capa de orquestación y el ritual de firma", no sobre la acción de firma en sí misma, cosa que indirectamente termina restringiendo el acceso a la firma propia y local, ya sea puntualizada o de alto volumen pero que no requiere de una capa de organización y orquestación adicional.

3. La normalización de la renuncia sobre la custodia del material criptográfico para que otros servicios la manejen por ti, por ejemplo: el acceso a la emisión de facturas, acceso al buzón tributario o acceso a plataformas de firmas de terceros, todos requieren **la entrega voluntaria del material en plano** a un tercero. Sin mencionar N cantidad de otros chanchuyos informales en los que se te pide hagas entrega de tu material criptográfico bajo la premisa del "confia en mi bro" y a los que lamentablemente se accede por desconocimiento sobre las capacidades e implicaciones posteriores que poseen, otorgan y adquieren este tipo de artefactos.

## En cuanto al funcionamiento.

e.firma CLI permite obtener como tope operativo un perfil de firma **PAdES-B-LTA** sobre un archivo PDF.

De manera muy resumida se entienden los perfiles de firma de la siguiente manera:

- **B**: Firma con certificado X.509, opcionalmente cadena de confianza de su PKI y hora del reloj del equipo del firmante.

- **L**: Firma con certificado X.509, cadena de confianza completa (sin raíz), evidencia OCSP/CRL proveniente de la PKI del firmante y hora del reloj del equipo del firmante. Permite corroborar que una determinada firma fue realizada mientras el certificado del firmante era válido sin depender a posteriori de la infraestructura de la PKI. Es progresión del perfil B (B -> L).

- **T**: Firma con sello de tiempo de TSA incrustado en la propia firma. Es el aspecto que otorga la "fecha cierta" al artefacto de firma situandolo en X momento del tiempo. Es técnicamente una "contrafirma" hecha por una autoridad de sellado de tiempo TSA. Literalmente: "Una TSA firma la firma del firmante, confiando en la TSA como autoridad imparcial para determinar el tiempo". Es complementario de los perfiles anteriores (ej: BT, LT).
    
- **A**: Sello de tiempo de TSA sobre 1 PDF con N cantidad de evidencias anteriores. Es el mismo tipo de sello de tiempo (TimeStampToken) pero aplicado sobre el PDF **JUNTO** a cualquier cantidad de evidencias criptográficas pre-existentes (multiples firmas, evidencias de validación, otros TSTs, etc.). Son incrementales. Generalmente ocurren al final de una sesión de firma para sellar todas las evidencias en un determinado momento del tiempo. Le da "fecha cierta" tanto al contenido del PDF junto a cualquier otra evidencia u operación hecha sobre este. Es complementario de los perfiles anteriores (ej: BA, LA, BTA, LTA)

e.firma CLI permite ejercer los 4 perfiles de firma dandole al firmante la libertad de elegir qué perfil quiere usar en sus firmas: Solo B, ascender de B a L, añadir T, añadir A en cualquiera de sus posibles combinaciones.

## Adicional

Bajo mi juicio y criterio subjetivo las firmas digitales basadas en criptografía son por mucho superiores a las autógrafas tradicionales, y teniendo en cuenta el hecho de que este tipo de artefactos están debidamente regulados por la ley no queda más que extender la difusión sobre las capacidades y caracteristicas que otorga el utilizar éstos elementos:

- Autenticidad de identidad.
- Integridad de los mensajes.
- No repudio criptográfico.
- Atribución de identidad con caracter legal.
- Multiplicador de eficiencia: Es mucho más eficiente firmar en digital que a mano.
- Transición paulatina factible: Reemplazar a las firmas fisicas en papel a las digital por e.firma/sello.

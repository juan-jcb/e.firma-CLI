import logging
from efcli import config

logger = logging.getLogger(__name__)

def validar_sintaxis(args_posicionales: list, modulo: dict) -> dict:
    '''Manejador de sintaxis para los argumentos posicionales recibidos por el usuario.

    - Validación Sintactica y Semántica: Se realizan validaciones generales sobre la SINTAXIS del comando en las flags
    proporcionadas. NO se evalua la funcionalidad de los argumentos para flags que reciben uno. Se comprueba si el
    comando está bien escrito de acuerdo a las flags funcionales del programa ANTES de una validación funcional real
    de los argumentos subyacentes.
    
    - Maneja los argumentos posicionales recibidos en el comando sin importar el orden en el que se declaren al ejecutarlo:
    En caso de haber flags de un mismo tipo repetidas, se usará UNICAMENTE el valor asociado a la PRIMERA flag del mismo
    tipo que haya sido escrita en el comando, sin importar si es flag corta o larga.
    
    - Se establece un órden de prioridad lógico sobre las flags válidas proporcionadas (e.g flags de help y versión tienen
    prioridad sobre las demás para mostrar su output)

    Args:
        args_posicionales (list): Argumentos posicionales del comando tal cual como se declaran.

    Returns:
        opciones_validas (dict): Diccionario con clave: flag funcional y valor: argumento asociado (sin evaluar funcionalidad)
    '''
    #logger.info('Evaluando Sintaxis de Argumentos Posicionales...')
    
    # Lógica de evaluación de parametros y argumentos.

    # 1. Si se reciben parametros, evaluar que haya incluidas flags válidas para el programa y descartar lo no útil.
    # Requiere de cargar todas las flags de programa de manera ordenada para hacer un escrutinio de filtrado adecuado.
    programa_flags = {}
    programa_flags.update(modulo['flags_de_argumento'])

    if modulo.get('flags_estaticas'):
        programa_flags.update(modulo['flags_estaticas'])
    if modulo.get('miscelanea'):
        programa_flags.update(modulo['miscelanea'])

    all_flags = [i for tupla in programa_flags.values() for i in tupla] # Lista de todas las flags del programa JUNTAS sin separación por contexto.
    #input_minimo = list(programa_flags['mnemonic'] + programa_flags['salt'])
    
    flags_de_argumento = [i for tupla in modulo['flags_de_argumento'].values() for i in tupla]
    #flags_estaticas = [i for tupla in programa['flags_estaticas'].values() for i in tupla]
    
    # 3. Descartar todo aquel parametro posicional que tenga estructura de flag, pero NO sea un flag PERMITIDA en el programa,
    # indpendientemente de si se hayan proporcionado flags y argumentos válidos.
    flags_invalidas = [i for i in args_posicionales if i not in all_flags and '-' in i]
    if flags_invalidas:
        invalidas = ''.join([f'\'{i}\' ' for i in flags_invalidas]) # queda un espacio extra al final jaja
        logger.error('Se ingresaron flags posicionales INVALIDAS: %sConsulte las opciones diponibles con: \'efcli -h, --help\'', invalidas)
        return False

    # 4. Sanitización de todas las posibles variantes de flag funcionales que puedan ser introducidas al comando.
    # 4.1 Filtro 1. Se descartan todos los argumentos que no sean flags funcionales del progama. Se mantiene el orden de declaración
    flags_validas = [i for i in args_posicionales if i in all_flags] # contiene flags literales repetidas y semánticas repetidas.
    
    # A partir de aquí solo existen flags permitidas para programa y se pretende remover los duplicados sintacticos y semánticos.
    # 4.2 Filtro 2. Filtrado de flags SINTACTICAS repetidas.
    sin_literales_repetidas = []
    vistas = set() # Se usa set auxiliar para ingresar solo las flags funcionales según el ORDEN en el que se declararon.
    for i in flags_validas:
        if i not in vistas:
            vistas.add(i) # Se descartan literales repetidas.
            sin_literales_repetidas.append(i)
        else:
            logger.warning('Ingreso flag LITERAL "%s" REPETIDA y NO será considerada en la derivación.', i)

    # 4.3 Filtro 3. Filtrado de flags SEMANTICAS repetidas.
    # Se realiza una validación por existencia en las tuplas de flags oficiales del programa para descartar las semánticas
    # repetidas.
    
    # se castea temporalmente a lista para insertar Flags booleanas internas de referencia.
    for i, j in programa_flags.items():
        programa_flags[i] = list(j)

    flags_funcionales = []
    for flag in sin_literales_repetidas:
        for lista_flags in programa_flags.values():
            if flag in lista_flags and lista_flags[0] != True:
                flags_funcionales.append(flag)
                lista_flags.insert(0, True)
                break
            elif flag in lista_flags and lista_flags[0] == True:
                logger.warning('Ingreso una flag SEMÁNTICA "%s" REPETIDA y NO será considerada en la derivación.', flag)

    # Se retornan las listas a su tipo de dato original tupla para evitar posterior mutación. 
    for i, j in programa_flags.items():
        programa_flags[i] = tuple(j) # Queda visible en el indice 0 de las tuplas, cuáles recibieron flag Booleana.

    # 5. Después de filtrado y sanitización de flags, se tiene unicamente lo funcional en cuanto a flags definidas para
    # el programa. En base a esto, se declara un órden de funcionalidad lógico para las flags válidas ingresadas:
    # 
    # - Se preservará el orden de declaración en los argumentos posicionales; leyendo el comando de izquierda a derecha,
    #   se utiliza únicamente la PRIMERA flag declarada de cada tipo, independientemente de si es flag corta o larga.
    # - Si se encuentran flags de ayuda o version en el comando, estas tienen prioridad sobre las demás, idependientemente
    #   de DONDE hayan sido declaradas en el comando.
    # - Si hay flags de argumento, se evualua la SINTAXIS de sus argumentos asociados para descartar argumentos invalidos.
    # - Se define un INPUT MINIMO VIABLE para que el programa sea funcional: Se requiere por lo menos de una flag 'mnemonic'
    #   y de una flag 'salt' con sus respectivos argumentos bien escritos para hacer una derivación minima funcional.
    
    # 5.1  Óden de prioridad: flags de help y de version tienen prioridad sobre otras para mostrar su output.
    for flag in flags_funcionales:
        if flag in config.FLAGS['miscelanea']['help']:
            print(config.MENSAJES_MISC['help'])
            return False
        if flag in config.FLAGS['miscelanea']['version']:
            print(config.MENSAJES_MISC['banner'])
            return False
    
    opciones_validas = {}

    # 5.2 revisión sintactica de las flags que reciben argumentos; revisión sobre LOS ARGUMENTOS.
    for flag in flags_funcionales:
        # Para flags de argumento: Se descartan argumentos sintacticamente invalidos. Esto NO evalua si el contenido del argumento es
        # FUNCIONAL para la flag, solo se prueba y descarta sintaxis general erronea en los argumentos recibidos.
        if flag in flags_de_argumento:
            # Evalua si existe el respectivo siguiente argumento posicional (dada la estructura natural y lógica de un argumento de flag)
            try:
                # Se usa .index() para usar solo la PRIMERA ocurrencia de flag de los argumentos posicionales del comando.
                argumento_de_flag = args_posicionales[args_posicionales.index(flag) + 1]
            except IndexError:
                logger.error('Flag "%s" fue decalara pero NECESITA un ARGUMENTO. Saliendo...', flag)
                return False
            else:                
                # Si el siguiente arg posicional existe, evaluar si este NO es OTRA flag existente.
                # Evita que se le pase como argumento una flag a otra flag.
                if '-' in argumento_de_flag:
                    logger.error('Flag "%s" recibió como argumento "%s". SINTAXIS INVALIDA!. Saliendo...', flag, argumento_de_flag)
                    return False
                else:
                    opciones_validas[flag] = argumento_de_flag
    
    # 5.5 Input minimo viable.
    # 
    # Posterior al manejo de sintaxis de flags y argumentos podemos afirmar que la entrada es SINTACTICA y SEMANTICAMENTE FUNCIONAL,
    # sin embargo se debe validar que, dentro de lo funcional, exista un input MINIMO VIABLE para hacer adecuadamente la derivación
    # de la clave criptográfica. Se requiere minimo una flag "mnemonic" y una flag "salt" con sus argumentos bien escritos.
    # 
    # - Se itera sobre "flags_funcionales" y se compara con las 4 variantes existentes; las 2 cortas y las 2 largas.
    #   Se usa un contador interno para señalizar cada ocurrencia de flag válida con las flags del input_minimo.
    # 
    # - Para cada incremento del contador se ELIMINA la coincidencia que lo hizo incrementar, esto evitaría incrementaciones
    #   fraudulentas causadas por entradas repetidas de una misma flag válida de input minimo.
    # 
    # - Así mismo se evalua si hubo al menos 2 coincidencias fiables (lo minimo necesario).
    #contador_minimo = 0
    #for i in flags_funcionales:
    #    if i in input_minimo:
    #        input_minimo.pop(input_minimo.index(i))
    #        contador_minimo += 1
    #if contador_minimo != 2:
    #    logger.error('No hay input minimo viable para derivación. Debe declarar \"--mnemonic\" y \"--salt\" junto a un argumento VALIDO.')
    #    return False
    #else:
    #    logger.info('Opciones Correctas.\n')
    #    return opciones_validas

    return opciones_validas
    
    # Esta función descarta aquellos valores basura que se hayan ingresado al comando y no sean sintacticamente ni semánticamente
    # necesarios. "opciones_validas" señaliza cuales son las flags consumibles por el programa:
    # - la clave (flag posicional existente con prefijos: '-' ó '--)
    # - valor (argumento asociado, aún sin validar funcionalidad subyacente)

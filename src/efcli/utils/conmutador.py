import logging
from efcli import config
from efcli.utils import sintaxis
from efcli.firma import firma_individual
from efcli.xdg import bootstrap # 2 reglones arriba [INFO] pikepdf C++ to Python logger bridge initialized

logger = logging.getLogger(__name__)

def entrada(sysargv: list):

    # 0. Caso principal: "efcli solo", función por defecto: firma con configuración guardada de usuario principal.
    if len(sysargv) <= 1:
        if bootstrap.check_env():
            stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['principal'])
            if not isinstance(stx, dict): # Asumiendo entorno válido, el caso funcional principal debería retornar un diccionario vacio.
                return
            firma_individual.hacer_firma()

        else:
            logger.warning("No ha inicializado aún el prorgama (use: 'efcli init').")
            return

    # 1. Modulo init
    elif sysargv[1] == 'init':
        if len(sysargv) == 2:
            if bootstrap.check_env():
                logger.info("Ya existe un entorno válido! (si quiere revisarlo: 'efcli init --check')")
            else:
                bootstrap.init() # "agregue pdfs a ruta base y empiece a utilizar"

        elif sysargv[2] == '--check':
            # Un entorno correcto se evalua 2 veces xd (la primera sin debug, la segunda con debug), pero eh funciona.
            if not bootstrap.check_env():
                logger.warning("No cuenta con un entorno viable (use: 'efcli init').")
                return
            bootstrap.check_env(log_level=logging.DEBUG)
        
        elif sysargv[2] == '--reset':
            if not bootstrap.check_env():
                logger.warning("No cuenta con un entorno viable (use: 'efcli init').")
                return
            bootstrap.reset_env()
        
        else:
            logger.warning("Ingrese una opción válida, vea opciones de modulo init con (efcli -h)")
            return None

    elif sysargv[1] == 'oscp':
        pass
    elif sysargv[1] == 'tsa':
        pass
    elif sysargv[1] == 'pdf':
        pass

    else:
        stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['principal'])
        if not stx:
            return

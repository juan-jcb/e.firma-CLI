import logging
from colorama import Fore
from efcli.firma import firma_individual
from efcli.utils import sintaxis
from efcli.env import config, bootstrap

def entrada(sysargv: list):

    # 0. Caso principal: "efcli solo", función por defecto: firma con configuración guardada.
    if len(sysargv) <= 1:
        if bootstrap.check_env():
            stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['principal'])
            if not isinstance(stx, dict): # Asumiendo entorno válido, el caso funcional principal debería retornar un diccionario vacio
                return False

            firma_individual.hacer_firma()
            return True
        else:
            print(f"[{Fore.LIGHTYELLOW_EX}ADVERTENCIA{Fore.WHITE}] No ha inicializado aún el prorgama (use: 'efcli init').")
            return False

    # 1. Modulo init
    elif sysargv[1] == 'init':
        if len(sysargv) == 2:
            if bootstrap.check_env():
                print(f"[{Fore.CYAN}INFO{Fore.WHITE}] Ya existe un entorno válido! (si quiere revisarlo: 'efcli init --check')")
            else:
                bootstrap.init() # "agregue pdfs a ruta base y empiece a utilizar"

        elif sysargv[2] == '--check':
            # Un entorno correcto se evalua 2 veces xd, pero eh funciona.
            if not bootstrap.check_env():
                print(f"[{Fore.LIGHTYELLOW_EX}ADVERTENCIA{Fore.WHITE}] No cuenta con un entorno viable (use: 'efcli init').")
                return False
            
            bootstrap.check_env(log_level=logging.DEBUG)
        
        elif sysargv[2] == '--reset':
            bootstrap.reset_env()
        
        return

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

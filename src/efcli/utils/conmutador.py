import logging
from efcli import config
from efcli.utils import sintaxis
from efcli.firma import firma_individual
from efcli.pki import ocsp
from efcli.xdg import bootstrap, usuarios # 2 reglones arriba [INFO] pikepdf C++ to Python logger bridge initialized

logger = logging.getLogger(__name__)

def entrada(sysargv: list):

    # 0. Caso principal: "efcli solo", función por defecto: firma con la configuración del usuario principal.
    if len(sysargv) <= 1:
        if len(sysargv) == 2:
            if not bootstrap.check_env():
                logger.warning("No ha inicializado aún el prorgama (use: 'efcli init').")
                return None
            firma_individual.hacer_firma()
            # Se evalua explicitamente el entorno aquí para no ensuciar la lógica de firma_individual con @eval.

        # TODO: desarrollar!, caso efcli con flags explicitas que sustituirían config de usuario temporalmente.
        if len(sysargv) > 2:
            stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['principal'])
            if not isinstance(stx, dict): 
                return None

    # 1. Submodulo init
    elif sysargv[1] == 'init':
        if len(sysargv) == 2:
            bootstrap.init() # "agregue pdfs a ruta base y empiece a utilizar"

        match sysargv[2]:
            case '--reset':
                bootstrap.reset_env()
            case '--check':
                if not bootstrap.check_env():
                    logger.warning("No cuenta con un entorno viable (use: 'efcli init').")
                    return None
                bootstrap.check_env(log_level=logging.DEBUG)
                # En efecto, un entorno correcto se evalua 2 veces, la primera sin debug para sacar
                # limpio el mensaje de error (si ocurriese), la segunda con debug para mostrar al usuario.
                # Se hace explicito con 'if not' aquí para no hacerlo circular usando @eval en check_env

            case _:
                logger.warning("Ingrese una opción válida, vea opciones de modulo init con (efcli -h)")
                return None

    # 2. Submodulo user
    elif sysargv[1] == 'user':
        if len(sysargv) == 2:
            logger.warning("Ingrese una opción válida, vea opciones de modulo user con (efcli -h)")
            return None

        match sysargv[2]:
            case '--whoami':
                usuarios.print_current_user()
            case '--list':
                usuarios.list_users()
            case '--change':
                usuarios.change_user()
            case '--add':
                usuarios.add_user()
            case '--del':
                usuarios.del_user()
            case '--conf':
                usuarios.print_current_user_conf()
            case '--toml':
                usuarios.print_current_user_toml()
            case _:
                logger.warning("Ingrese una opción válida, vea opciones de modulo user con (efcli -h)")
                return None

    elif sysargv[1] == 'ocsp':
        if len(sysargv) == 2:
            logger.warning("Ingrese una opción válida, vea opciones de modulo oscp con (efcli -h)")
            return None

        match sysargv[2]:
            case '--request':
                if not bootstrap.check_env():
                    logger.warning("No ha inicializado el programa! (use efcli init)")
                    return None

                if len(sysargv) == 3: # es request propia.
                    ocsp.nueva_request(propia=True)

                else: # será request con CERT distinto.
                    stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['submodulos']['ocsp'])
                    if not stx: 
                        return None
                    ocsp.nueva_request(cert_file=stx['--request'])

            case '--validez':
                stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['submodulos']['ocsp'])
                if not stx: 
                    return None
                ocsp.imprimir_estado(resp_file=stx['--validez'])

            case '--parse':
                stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['submodulos']['ocsp'])
                if not stx: 
                    return None
                ocsp.parse_ocsp(resp_file=stx['--parse'])
                
            case _:
                logger.warning("Ingrese una opción válida, vea opciones de modulo user con (efcli -h)")
                return None

    elif sysargv[1] == 'tsa':
        pass
    elif sysargv[1] == 'pdf':
        pass

    else:
        stx = sintaxis.validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['principal'])
        if not stx:
            return

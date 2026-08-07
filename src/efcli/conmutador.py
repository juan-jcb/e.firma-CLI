import logging

from efcli import patches # no se usa de forma "tradicional" pero se declara aquí para que siempre se cargue al ejecutar main.
from efcli import config

# no me termina de agradar esta forma de importar, pero desde un inicio no tendría q estár importando aquí modulos posteriores xD
from efcli.core.sintaxis import validar_sintaxis
from efcli.ocsp.ocsp_cli import nueva_request, imprimir_respuesta, imprimir_estado
from efcli.xdg.usuarios import add_user, del_user, change_user, reconf_user, list_users, print_current_user, print_current_user_conf, print_current_user_toml
from efcli.xdg.cas import add_ca, del_ca, list_ca

from efcli.firma import firma_individual
from efcli.xdg.bootstrap import check_env, reset_env, init

logger = logging.getLogger(__name__)

def entrada(sysargv: list):

    # 0. Caso principal: "efcli solo", función por defecto: firma con la configuración del usuario principal.
    if len(sysargv) <= 1:
        if len(sysargv) == 1:
            if not check_env():
                logger.warning("No ha inicializado aún el prorgama (use: 'efcli init').")
                return None
            firma_individual.hacer_firma()
            # Se evalua explicitamente el entorno aquí para no ensuciar la lógica de firma_individual con @eval.

        # TODO: desarrollar!, caso efcli con flags explicitas que sustituirían config de usuario temporalmente.
        if len(sysargv) > 2:
            stx = validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['principal'])
            if not isinstance(stx, dict): 
                return None

    # 1. Submodulo init
    elif sysargv[1] == 'init':
        if len(sysargv) <= 2:
            if check_env():
                logger.info("Ya existe un entorno válido! (si quiere revisarlo: 'efcli init --check')")
                return None
            init() # "agregue pdfs a ruta base y empiece a utilizar"

        else:
            match sysargv[2]:
                case '--reset':
                    reset_env()
                case '--check':
                    if not check_env():
                        logger.warning("No cuenta con un entorno viable (use: 'efcli init').")
                        return None
                    check_env(log_level=logging.DEBUG)
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
                print_current_user()
            case '--list':
                list_users()
            case '--change':
                change_user()
            case '--reconf':
                reconf_user()
            case '--add':
                add_user()
            case '--del':
                del_user()
            case '--conf':
                print_current_user_conf()
            case '--toml':
                print_current_user_toml()
            case _:
                logger.warning("Ingrese una opción válida, vea opciones de modulo user con (efcli -h)")
                return None

    # 3. "Submodulo" pki
    elif sysargv[1] == 'pki':
        if len(sysargv) == 2:
            logger.warning("Ingrese una opción válida, vea opciones de modulo pki con (efcli -h)")
            return None

        match sysargv[2]:
            case '--list':
                list_ca()
            case '--add':
                stx = validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['submodulos']['pki'])
                if not stx:
                    return None
                add_ca(cafile=stx['--add'])
            case '--del':
                del_ca()

    # 4. Submodulo ocsp
    elif sysargv[1] == 'ocsp':
        if len(sysargv) == 2:
            logger.warning("Ingrese una opción válida, vea opciones de modulo oscp con (efcli -h)")
            return None

        match sysargv[2]:
            case '--request':
                if not check_env():
                    logger.warning("No ha inicializado el programa! (use efcli init)")
                    return None

                if len(sysargv) == 3: # es request propia.
                    nueva_request(propia=True)

                else: # será request con CERT distinto.
                    stx = validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['submodulos']['ocsp'])
                    if not stx: 
                        return None
                    nueva_request(cert_file=stx['--request'])

            case '--validez':
                stx = validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['submodulos']['ocsp'])
                if not stx: 
                    return None
                imprimir_estado(response=stx['--validez'])

            case '--parse':
                stx = validar_sintaxis(args_posicionales=sysargv, modulo=config.FLAGS['submodulos']['ocsp'])
                if not stx: 
                    return None
                imprimir_respuesta(resp_file=stx['--parse'])
                
            case _:
                logger.warning("Ingrese una opción válida, vea opciones de modulo user con (efcli -h)")
                return None

    elif sysargv[1] == 'tsa':
        pass
    elif sysargv[1] == 'pdf':
        pass

    else:
        base = config.FLAGS['principal']
        base['miscelanea'] = config.FLAGS['miscelanea'] 
        stx = validar_sintaxis(args_posicionales=sysargv, modulo=base)
        if not stx:
            return

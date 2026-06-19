import logging
from functools import wraps

logger = logging.getLogger(__name__)

def salida_limpia():
    def wrapper(fn):
        def inner(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except KeyboardInterrupt:
                print("\nCTRL+C Recibido. Saliendo...")
                exit()
        return inner
    return wrapper

def eval(fn_condicion, si_false: str):
    def decorador(fn_real):
        @wraps(fn_real)
        def wrapper(*args, **kwargs):
            if not fn_condicion(*args, **kwargs):
                logger.warning(si_false)
                return False
            return fn_real(*args, **kwargs)
        return wrapper
    return decorador
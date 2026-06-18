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
import re

# Alfanumérico, input vacio permitido
ALFANUMERICO = re.compile(r'^[A-Za-z0-9]*$')
# Alfanumérico, puntos, guiones medio/bajo, espacios entremedias, sin espacios al inicio/final.
ASCII_SIMPLE = re.compile(r'^[A-Za-z0-9_.-]+(?: [A-Za-z0-9_.-]+)*$')
# Alfabeto español, espacios entremedias, sin espacios al inicio/final, input vacio permitido.
SPANISH = re.compile(r'^[A-Za-zÁÉÍÓÚáéíóúÑñÜü0-9_.-]*(?: [A-Za-zÁÉÍÓÚáéíóúÑñÜü0-9_.-]+)*$')
# Correos (simple), input vacio permitido.
CORREOS = re.compile(r'^(?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})?$')

def input_regex(regex: re.Pattern, mensaje: str, pista: str):
    while True:
        _ = input(mensaje).strip()
        if not regex.match(_):
            print(f"Entrada inválida. Se permite: {pista}")
            continue
        break
    return _

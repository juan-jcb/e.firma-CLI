from pathlib import Path

def guardar_archivos(*args, **kwargs) -> None:
    """
    Función generalizada para almacenar archivos en X ruta
    asumiendo que el contenido a almacenar existe y es bytes.

    La lógica de ruta, extensión y número de archivos se
    determina según la organización de los argumentos en
    la llamada.
    
    :param args:
        Indice 0: :class:`str` de ruta en sistema. Si ruta no
        existe se crean directorios intermedios, si ya existe
        se usa ese sin sobreescribir.
        
        Indice 1: :class:`str` para extensión de archivo (sin `.`)

    :param kwargs:
        Pares "clave:valor" donde `clave` es nombre del archivo
        y `valor` son los :class:`Bytes` a escribir.
    """
    ruta = Path(args[0])
    ext = args[1]
    
    if not ruta.is_dir():
        ruta.mkdir(parents=True)
    for i, j in kwargs.items():
        with open(f'{ruta}/{i}.{ext}', 'wb') as b:
            b.write(j)

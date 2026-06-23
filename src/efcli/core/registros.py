import logging
from contextlib import contextmanager
from colorama import init, Fore, Style

init(autoreset=True)

class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG:    Fore.GREEN,
        logging.INFO:     Fore.CYAN,
        logging.WARNING:  Fore.LIGHTYELLOW_EX,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        record.asctime = self.formatTime(record, self.datefmt)
        level_color = self.LEVEL_COLORS.get(record.levelno, "")
        time_color  = Fore.LIGHTCYAN_EX
        msg_color   = Fore.WHITE
        record.levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"
        record.asctime   = f"{time_color}{record.asctime}{Style.RESET_ALL}"
        record.msg       = f"{msg_color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter("[%(levelname)s] %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

logger = logging.getLogger(__name__)

@contextmanager
def modded_logs(
    target_logger: logging.Logger=None,
    fmt: str = "[%(levelname)s] %(message)s",
    level=logging.INFO,
    formatter_class=ColorFormatter
):
    """
    Cambia temporalmente el formato del logger mientras se esté dentro de cualquier
    `with`, y al salir del bloque se restaura el formato original automáticamente.

    Args:
        fmt: Formato deseado dentro del bloque with.
        target_logger: Logger a modificar. Si no se indica, usa el root logger.
        formatter_class: clase para modificar el formato.

    fmt controla la estructura textual
    formatter_class controla los colores
    se combinan libremente en cada with.
    """
    target = target_logger or logging.root
    handlers = target.handlers or logging.root.handlers
    originales = [(h, h.formatter) for h in handlers] # Guardar formatters originales

    # Aplicar nuevo formato
    for h in handlers:
        h.setFormatter(formatter_class(fmt))
    try:
        target.setLevel(level)
        yield target
    
    # Restaurar siempre incluso si ocurre una excepción
    finally:
        for h, fmt_orig in originales:
            h.setFormatter(fmt_orig)

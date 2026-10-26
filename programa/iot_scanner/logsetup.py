"""
Registro (logging) común a la CLI y a la GUI. Propuesta de Qwen: sustituir los
print() de progreso por el módulo logging.

- Consola (stderr): mensajes de progreso con el estilo de siempre ("[*] ...",
  "[!] ..."), así la salida estándar queda solo para la tabla y el resumen.
- Fichero opcional (--log): todo, incluido DEBUG, con fecha y módulo.

La tabla y el resumen del informe (report.print_*) siguen usando print(): son la
salida del programa, no mensajes de registro.
"""

import logging

LOGGER_NAME = "iot_scanner"
FILE_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


class ConsoleFormatter(logging.Formatter):
    """[.] depuración, [*] información, [!] avisos y errores."""

    PREFIX = {logging.DEBUG: "[.]", logging.INFO: "[*]"}

    def format(self, record):
        prefix = self.PREFIX.get(record.levelno, "[!]")
        return f"{prefix} {record.getMessage()}"


def setup_logging(verbose=False, log_file=None, extra_handler=None):
    """
    Configura el logger "iot_scanner" y devuelve los handlers añadidos.

    verbose: muestra también DEBUG en consola. log_file: guarda todo en ese fichero.
    extra_handler: un handler propio en lugar de la consola (la GUI lo usa para su
    pestaña Registro).
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for h in list(logger.handlers):   # evita duplicados si se llama dos veces
        logger.removeHandler(h)
        h.close()

    console = extra_handler or logging.StreamHandler()   # stderr por defecto
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    if console.formatter is None:
        console.setFormatter(ConsoleFormatter())
    handlers = [console]

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(FILE_FORMAT))
        handlers.append(fh)

    for h in handlers:
        logger.addHandler(h)
    return handlers

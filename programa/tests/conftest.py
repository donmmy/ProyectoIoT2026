import logging

import pytest

from iot_scanner.logsetup import LOGGER_NAME


@pytest.fixture(autouse=True)
def _reset_logging():
    """La CLI y la GUI configuran el logger "iot_scanner" (handlers propios y sin propagar).
    Se deja como estaba tras cada test para que caplog siga recibiendo los mensajes."""
    yield
    logger = logging.getLogger(LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    logger.propagate = True
    logger.setLevel(logging.NOTSET)

# expect: none
import logging

log = logging.getLogger(__name__)


def load(path):
    try:
        return open(path).read()
    except OSError:
        log.exception("could not read %s", path)
        return ""

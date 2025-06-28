import logging, os, sys, json, time
from settings import settings

_DEFAULT_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

def configure() -> None:
    level = os.getenv("LOG_LEVEL", settings.LOG_LEVEL).upper()
    logging.basicConfig(
        level=level,
        format=_DEFAULT_FMT,
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

def json_log(record: logging.LogRecord) -> str:
    return json.dumps(
        {
            "ts": time.time(),
            "level": record.levelname,
            "name": record.name,
            "msg": record.getMessage(),
        }
    )
__all__ = ["configure", "json_log"] 
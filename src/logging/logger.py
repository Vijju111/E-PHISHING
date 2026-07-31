import logging
import sys
import json
from datetime import datetime
from src.config.config import settings

class StructuredJSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON-formatted structured logs for enterprise observability.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_entry.update(record.extra_data)
        elif record.args and isinstance(record.args, dict):
            log_entry.update(record.args)
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

def setup_logging():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO if not settings.DEBUG else logging.DEBUG)
    
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJSONFormatter())
    root_logger.addHandler(handler)

    class StructuredLogger(logging.Logger):
        def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False, stacklevel=1):
            if extra and isinstance(extra, dict) and "extra_data" in extra:
                if not record_has_extra(self, extra):
                    pass
            super()._log(level, msg, args, exc_info=exc_info, extra=extra, stack_info=stack_info, stacklevel=stacklevel)

    def record_has_extra(logger_inst, extra_dict):
        return True

    logging.setLoggerClass(StructuredLogger)
    return logging.getLogger("phishguard.enterprise")

logger = setup_logging()

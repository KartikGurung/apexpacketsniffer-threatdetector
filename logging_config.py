import logging
import json
import os
from logging.handlers import RotatingFileHandler

class JsonFormatter(logging.Formatter):
    def format(self, record):
        record_dict = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage()
        }
        return json.dumps(record_dict)

log_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(log_dir, "app.log")
handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("apex")
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(handler)

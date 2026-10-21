import logging
import json
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

log_file = "app.log"
handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("apex")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

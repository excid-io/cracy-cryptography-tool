import logging
import os
from http.server import HTTPServer

from http_handler import SemgrepRequestHandler


HOST = "0.0.0.0"
PORT = int(os.environ.get("SEMGREP_SERVER_PORT", "9091"))
CONFIGS_DIR = os.environ.get("SEMGREP_CONFIGS_DIR", "/configs")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), SemgrepRequestHandler)

    logger.info("Semgrep server listening on http://%s:%s", HOST, PORT)
    logger.info("Semgrep configs directory: %s", CONFIGS_DIR)

    server.serve_forever()
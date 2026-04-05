import logging
import threading

import uvicorn

from app.runtime.server import app

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def open_browser_after_startup(url: str, delay_seconds: float = 1.5):
    import webbrowser

    threading.Timer(delay_seconds, lambda: webbrowser.open(url)).start()


def main() -> None:

    host = "127.0.0.1"
    port = 8080
    url = f"http://{host}:{port}"

    print(f"\n  OpenCircuit starting at {url}")
    print(f"  Opening browser...\n")

    open_browser_after_startup(url)

    uvicorn.run(app, host=host, port=port, log_level="info")

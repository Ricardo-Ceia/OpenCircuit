import logging
import threading
from cli_flow import print_display, run_identify_flow

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def main():
    import uvicorn
    import webbrowser

    host = "127.0.0.1"
    port = 8080
    url = f"http://{host}:{port}"

    print(f"\n  OpenCircuit starting at {url}")
    print(f"  Opening browser...\n")

    # Open browser after a short delay
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run("server:app", host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()

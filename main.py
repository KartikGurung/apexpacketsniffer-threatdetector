import sys
import os
import threading
import time
import uvicorn
import webview
from config import HOST, PORT
import os
import threading
import time
import uvicorn
import webview

def start_server():
    """
    Launches Uvicorn to serve the FastAPI application.
    """
    from config import HOST, PORT
    config = uvicorn.Config(
        "backend.server:app",
        host=HOST,
        port=PORT,
        log_level="warning",
        reload=False
    )
    server = uvicorn.Server(config)
    server.run()

if __name__ == "__main__":
    # Windows admin check
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("Administrator privileges required on Windows for packet capture.")
    print("Starting backend web server...")
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)
    print("Launching Desktop Application GUI...")
    webview.create_window(
        title="Apex Network Sniffer & Threat Detector",
        url=f"http://{HOST}:{PORT}",
        width=1280,
        height=850,
        resizable=True,
        min_size=(1024, 700)
    )
    webview.start()
    print("Apex Packet Sniffer shutdown successfully.")

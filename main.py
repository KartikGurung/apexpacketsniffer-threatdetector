import sys
import os
import threading
import time
import uvicorn
import webview
from config import HOST, PORT

def start_server():
    """
    Launches Uvicorn to serve the FastAPI application.
    """
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
    is_admin = True
    if os.name == "nt":
        import ctypes
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False

        if not is_admin:
            print("\n" + "=" * 72)
            print("[NOTICE] Running without Administrator privileges.")
            print("         Capturing live promiscuous packets with Npcap requires Admin rights.")
            print("         For full packet capture, restart PowerShell/terminal as Administrator.")
            print("=" * 72 + "\n")

    print(f"Starting backend web server on http://{HOST}:{PORT}...")
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

import threading
import os
from scapy.all import AsyncSniffer, sniff, wrpcap, conf, get_if_list

def get_interfaces():
    """
    Lists all available network interfaces on the system.
    Tries to retrieve human-readable names and IP/MAC addresses.
    """
    interfaces = []
    
    # Try Windows specific interface retrieval first
    try:
        from scapy.arch.windows import get_windows_if_list
        win_ifaces = get_windows_if_list()
        for face in win_ifaces:
            guid = face.get("guid") or face.get("name")
            desc = face.get("description") or face.get("name")
            ips = face.get("ips", [])
            ip = ips[0] if ips else "No IP"
            mac = face.get("mac") or "No MAC"
            
            # Filter out loopback or meaningless adapters if they clutter, but keep them for sniffing
            interfaces.append({
                "id": guid,
                "name": desc,
                "ip": ip,
                "mac": mac,
                "status": "Active" if ip != "No IP" else "Inactive"
            })
    except Exception as e:
        print(f"Windows interfaces fetch failed: {e}. Falling back to conf.ifaces.")
        # Fallback to Scapy conf.ifaces
        try:
            for name, iface in conf.ifaces.items():
                interfaces.append({
                    "id": iface.name,
                    "name": iface.description or iface.name,
                    "ip": iface.ip or "No IP",
                    "mac": iface.mac or "No MAC",
                    "status": "Active" if iface.ip else "Inactive"
                })
        except Exception as e2:
            print(f"Scapy conf.ifaces failed: {e2}. Falling back to get_if_list.")
            # Fallback to basic interface list
            try:
                for name in get_if_list():
                    interfaces.append({
                        "id": name,
                        "name": name,
                        "ip": "Unknown",
                        "mac": "Unknown",
                        "status": "Unknown"
                    })
            except Exception as e3:
                print(f"Basic get_if_list failed: {e3}")
    
    # Ensure there is at least a loopback interface
    if not interfaces:
        interfaces.append({
            "id": "loopback",
            "name": "Loopback Pseudo-Interface",
            "ip": "127.0.0.1",
            "mac": "00:00:00:00:00:00",
            "status": "Active"
        })
        
    return interfaces


import datetime

def log_debug(msg):
    try:
        log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().isoformat()} - SNIFFER: {msg}\n")
    except Exception as e:
        print(f"Logging failed: {e}")

class LiveSniffer:
    """
    Thread-safe packet sniffer utilizing Scapy's AsyncSniffer.
    Runs asynchronously to prevent locking the web server and allows clean stopping
    even during idle network traffic.
    """
    def __init__(self, packet_callback):
        self.packet_callback = packet_callback
        self.async_sniffer = None
        self.is_running = False
        self.interface = None
        self.filter_str = None
        self.captured_packets = []  # Keep a buffer of packet objects for PCAP export
        self._lock = threading.Lock()

    def _resolve_interface(self, iface_name):
        if not iface_name:
            return None
        for iface_key, iface_obj in conf.ifaces.items():
            if (iface_name == iface_key or 
                iface_name == iface_obj.name or 
                iface_name == getattr(iface_obj, "guid", "") or
                iface_name == getattr(iface_obj, "network_name", "")):
                return iface_obj
        return iface_name

    def _handle_packet(self, packet):
        with self._lock:
            # Store packet for PCAP export. Limit queue to prevent memory leak
            self.captured_packets.append(packet)
            if len(self.captured_packets) > 10000:
                self.captured_packets.pop(0)
        
        # Fire callback to process packet
        try:
            self.packet_callback(packet)
        except Exception as e:
            print(f"Error executing packet callback: {e}")

    def start(self, interface=None, filter_str=None):
        with self._lock:
            if self.is_running:
                log_debug("start() called but sniffer is already running.")
                return False
            
            self.interface = interface
            self.filter_str = filter_str
            
            sniff_args = {
                "prn": self._handle_packet,
                "store": False
            }
            if self.interface:
                resolved = self._resolve_interface(self.interface)
                log_debug(f"Resolved interface '{self.interface}' to: {resolved}")
                sniff_args["iface"] = resolved
            if self.filter_str and self.filter_str.strip():
                sniff_args["filter"] = self.filter_str.strip()

            try:
                self.async_sniffer = AsyncSniffer(**sniff_args)
                self.async_sniffer.start()
                self.is_running = True
                log_debug(f"AsyncSniffer started on interface: {interface}")
                return True
            except Exception as e:
                log_debug(f"Failed to start AsyncSniffer: {e}")
                self.is_running = False
                self.async_sniffer = None
                return False

    def stop(self):
        with self._lock:
            if not self.is_running or not self.async_sniffer:
                return False
            try:
                self.async_sniffer.stop()
            except Exception as e:
                log_debug(f"Exception stopping AsyncSniffer: {e}")
            self.is_running = False
            self.async_sniffer = None
            log_debug("AsyncSniffer stopped successfully.")
            return True

    def clear(self):
        with self._lock:
            self.captured_packets.clear()

    def save_pcap(self, filepath):
        with self._lock:
            if not self.captured_packets:
                return False
            try:
                wrpcap(filepath, self.captured_packets)
                return True
            except Exception as e:
                print(f"Failed to write PCAP file: {e}")
                return False

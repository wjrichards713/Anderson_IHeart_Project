"""
TCP/UDP Protocol Bridge
Bridges a TCP connection (SAS/USI protocol) with UDP (Soundboard commands).
Translates string mappings bidirectionally between TCP and UDP.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import json
import os
import sys
from collections import deque


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_config_path():
    """Return config file path next to the executable (or script)."""
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "bridge_config.json")


def encode_special(display_string):
    """Convert a display string containing \\xNN escape sequences into raw bytes.

    For example the user types  \\x1a201003077  in the GUI and this function
    returns  b'\\x1a201003077'  (with the first byte being 0x1A, i.e. Ctrl-Z).
    """
    result = bytearray()
    i = 0
    while i < len(display_string):
        if display_string[i:i + 2] == '\\x' and i + 4 <= len(display_string):
            hex_chars = display_string[i + 2:i + 4]
            try:
                result.append(int(hex_chars, 16))
                i += 4
                continue
            except ValueError:
                pass
        result.append(ord(display_string[i]))
        i += 1
    return bytes(result)


# ---------------------------------------------------------------------------
# TCP Client
# ---------------------------------------------------------------------------

class TCPClient:
    """Manages a TCP socket connection in a background thread."""

    def __init__(self, on_data=None, on_status=None):
        self.on_data = on_data          # callback(str)
        self.on_status = on_status      # callback(bool)
        self._socket = None
        self._thread = None
        self._running = False
        self.connected = False

    def connect(self, ip, port):
        if self.connected:
            return
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(5)
            self._socket.connect((ip, int(port)))
            self._socket.settimeout(None)
            self._running = True
            self.connected = True
            if self.on_status:
                self.on_status(True)
            self._thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._thread.start()
        except Exception as e:
            self.connected = False
            if self.on_status:
                self.on_status(False)
            raise ConnectionError(f"TCP connect failed: {e}")

    def disconnect(self):
        self._running = False
        self.connected = False
        try:
            if self._socket:
                self._socket.close()
        except Exception:
            pass
        self._socket = None
        if self.on_status:
            self.on_status(False)

    def send(self, data_str):
        """Send data over TCP.  Handles \\xNN escapes and appends CR."""
        if not self.connected or not self._socket:
            return
        raw = encode_special(data_str) + b'\r'
        try:
            self._socket.sendall(raw)
        except Exception:
            self.disconnect()

    def _recv_loop(self):
        buf = ""
        while self._running:
            try:
                data = self._socket.recv(4096)
                if not data:
                    break
                buf += data.decode('latin-1')
                while '\r' in buf:
                    msg, buf = buf.split('\r', 1)
                    msg = msg.strip('\n').strip()
                    if msg and self.on_data:
                        self.on_data(msg)
            except OSError:
                break
        self.connected = False
        if self.on_status:
            self.on_status(False)


# ---------------------------------------------------------------------------
# UDP Socket
# ---------------------------------------------------------------------------

class UDPSocket:
    """Manages a UDP socket for send (broadcast) and receive."""

    def __init__(self, on_data=None, on_status=None):
        self.on_data = on_data
        self.on_status = on_status
        self._socket = None
        self._thread = None
        self._running = False
        self.bound = False
        self._send_ip = None
        self._send_port = None

    def connect(self, ip, port):
        """Bind to the given port for receiving and store target ip/port for sending."""
        if self.bound:
            return
        try:
            self._send_ip = ip
            self._send_port = int(port)
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(("", self._send_port))
            self._running = True
            self.bound = True
            if self.on_status:
                self.on_status(True)
            self._thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._thread.start()
        except Exception as e:
            self.bound = False
            if self.on_status:
                self.on_status(False)
            raise ConnectionError(f"UDP bind failed: {e}")

    def disconnect(self):
        self._running = False
        self.bound = False
        try:
            if self._socket:
                self._socket.close()
        except Exception:
            pass
        self._socket = None
        if self.on_status:
            self.on_status(False)

    def send(self, data_str):
        """Send a UDP datagram to the configured target."""
        if not self.bound or not self._socket:
            return
        raw = data_str.encode('latin-1')
        try:
            self._socket.sendto(raw, (self._send_ip, self._send_port))
        except Exception:
            pass

    def _recv_loop(self):
        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                msg = data.decode('latin-1').strip()
                if msg and self.on_data:
                    self.on_data(msg)
            except OSError:
                break
        self.bound = False
        if self.on_status:
            self.on_status(False)


# ---------------------------------------------------------------------------
# Mapping Engine
# ---------------------------------------------------------------------------

class MappingEngine:
    """Holds the list of mappings and performs lookups."""

    def __init__(self):
        self.mappings = []  # list of dicts: {direction, tcp_value, udp_value}

    def process_tcp(self, msg):
        """Return list of UDP values to send for a received TCP message."""
        results = []
        for m in self.mappings:
            if m["direction"] == "TCP -> UDP" and m["tcp_value"] and msg == m["tcp_value"]:
                results.append(m["udp_value"])
        return results

    def process_udp(self, msg):
        """Return list of TCP values to send for a received UDP message."""
        results = []
        for m in self.mappings:
            if m["direction"] == "UDP -> TCP" and m["udp_value"] and msg == m["udp_value"]:
                results.append(m["tcp_value"])
        return results


# ---------------------------------------------------------------------------
# GUI Application
# ---------------------------------------------------------------------------

class BridgeApp(tk.Tk):

    MAX_LOG_LINES = 1000
    LOG_FLUSH_MS = 100

    def __init__(self):
        super().__init__()
        self.title("TCP / UDP Protocol Bridge")
        self.geometry("960x720")
        self.minsize(800, 600)

        self.tcp_client = TCPClient(
            on_data=lambda m: self.after(0, self._on_tcp_data, m),
            on_status=lambda s: self.after(0, self._on_tcp_status, s),
        )
        self.udp_socket = UDPSocket(
            on_data=lambda m: self.after(0, self._on_udp_data, m),
            on_status=lambda s: self.after(0, self._on_udp_status, s),
        )
        self.engine = MappingEngine()

        # Log queues for throttled display updates
        self._tcp_log_q = deque(maxlen=200)
        self._udp_log_q = deque(maxlen=200)

        self._build_gui()
        self._load_config()
        self._flush_logs()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---- GUI construction --------------------------------------------------

    def _build_gui(self):
        # ---------- Connection area ----------
        conn_frame = tk.Frame(self)
        conn_frame.pack(fill=tk.X, padx=8, pady=4)

        # TCP
        tcp_lf = tk.LabelFrame(conn_frame, text="TCP Connection", padx=6, pady=4)
        tcp_lf.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        tk.Label(tcp_lf, text="IP:").grid(row=0, column=0, sticky=tk.E)
        self.tcp_ip_var = tk.StringVar()
        tk.Entry(tcp_lf, textvariable=self.tcp_ip_var, width=18).grid(row=0, column=1, padx=2)
        tk.Label(tcp_lf, text="Port:").grid(row=0, column=2, sticky=tk.E)
        self.tcp_port_var = tk.StringVar()
        tk.Entry(tcp_lf, textvariable=self.tcp_port_var, width=8).grid(row=0, column=3, padx=2)
        self.tcp_conn_btn = tk.Button(tcp_lf, text="Connect", command=self._tcp_connect)
        self.tcp_conn_btn.grid(row=0, column=4, padx=4)
        self.tcp_disc_btn = tk.Button(tcp_lf, text="Disconnect", state=tk.DISABLED, command=self._tcp_disconnect)
        self.tcp_disc_btn.grid(row=0, column=5, padx=2)
        self.tcp_status_lbl = tk.Label(tcp_lf, text="Disconnected", fg="red")
        self.tcp_status_lbl.grid(row=0, column=6, padx=6)

        # UDP
        udp_lf = tk.LabelFrame(conn_frame, text="UDP Connection", padx=6, pady=4)
        udp_lf.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))

        tk.Label(udp_lf, text="IP:").grid(row=0, column=0, sticky=tk.E)
        self.udp_ip_var = tk.StringVar()
        tk.Entry(udp_lf, textvariable=self.udp_ip_var, width=18).grid(row=0, column=1, padx=2)
        tk.Label(udp_lf, text="Port:").grid(row=0, column=2, sticky=tk.E)
        self.udp_port_var = tk.StringVar()
        tk.Entry(udp_lf, textvariable=self.udp_port_var, width=8).grid(row=0, column=3, padx=2)
        self.udp_conn_btn = tk.Button(udp_lf, text="Connect", command=self._udp_connect)
        self.udp_conn_btn.grid(row=0, column=4, padx=4)
        self.udp_disc_btn = tk.Button(udp_lf, text="Disconnect", state=tk.DISABLED, command=self._udp_disconnect)
        self.udp_disc_btn.grid(row=0, column=5, padx=2)
        self.udp_status_lbl = tk.Label(udp_lf, text="Disconnected", fg="red")
        self.udp_status_lbl.grid(row=0, column=6, padx=6)

        # ---------- Log area ----------
        log_frame = tk.Frame(self)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        tcp_log_lf = tk.LabelFrame(log_frame, text="TCP Data Log")
        tcp_log_lf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4))
        self.tcp_log = scrolledtext.ScrolledText(tcp_log_lf, state=tk.DISABLED, height=10, wrap=tk.WORD, font=("Consolas", 9))
        self.tcp_log.pack(fill=tk.BOTH, expand=True)

        udp_log_lf = tk.LabelFrame(log_frame, text="UDP Data Log")
        udp_log_lf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0))
        self.udp_log = scrolledtext.ScrolledText(udp_log_lf, state=tk.DISABLED, height=10, wrap=tk.WORD, font=("Consolas", 9))
        self.udp_log.pack(fill=tk.BOTH, expand=True)

        # ---------- Mapping area ----------
        map_outer = tk.LabelFrame(self, text="String Mappings", padx=6, pady=4)
        map_outer.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Header row
        hdr = tk.Frame(map_outer)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="Direction", width=14, anchor=tk.W, font=("", 9, "bold")).pack(side=tk.LEFT, padx=2)
        tk.Label(hdr, text="TCP Value", width=30, anchor=tk.W, font=("", 9, "bold")).pack(side=tk.LEFT, padx=2)
        tk.Label(hdr, text="UDP Value", width=30, anchor=tk.W, font=("", 9, "bold")).pack(side=tk.LEFT, padx=2)
        tk.Button(hdr, text="+ Add Row", command=self._add_mapping_row).pack(side=tk.RIGHT, padx=4)

        # Scrollable mapping rows
        self._map_canvas = tk.Canvas(map_outer, highlightthickness=0)
        self._map_scrollbar = ttk.Scrollbar(map_outer, orient=tk.VERTICAL, command=self._map_canvas.yview)
        self._map_inner = tk.Frame(self._map_canvas)
        self._map_inner.bind("<Configure>", lambda e: self._map_canvas.configure(scrollregion=self._map_canvas.bbox("all")))
        self._map_canvas.create_window((0, 0), window=self._map_inner, anchor=tk.NW)
        self._map_canvas.configure(yscrollcommand=self._map_scrollbar.set)

        self._map_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._map_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Enable mousewheel scrolling
        self._map_canvas.bind("<Enter>", lambda e: self._map_canvas.bind_all("<MouseWheel>", self._on_map_mousewheel))
        self._map_canvas.bind("<Leave>", lambda e: self._map_canvas.unbind_all("<MouseWheel>"))

        self.mapping_rows = []  # list of dicts with widgets

        # ---------- Status bar ----------
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN, padx=6).pack(fill=tk.X, side=tk.BOTTOM)

    def _on_map_mousewheel(self, event):
        self._map_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ---- Mapping rows ------------------------------------------------------

    def _add_mapping_row(self, direction="TCP -> UDP", tcp_val="", udp_val=""):
        row_frame = tk.Frame(self._map_inner)
        row_frame.pack(fill=tk.X, pady=1)

        dir_var = tk.StringVar(value=direction)
        dir_cb = ttk.Combobox(row_frame, textvariable=dir_var, values=["TCP -> UDP", "UDP -> TCP"],
                              state="readonly", width=12)
        dir_cb.pack(side=tk.LEFT, padx=2)

        tcp_var = tk.StringVar(value=tcp_val)
        tcp_entry = tk.Entry(row_frame, textvariable=tcp_var, width=32)
        tcp_entry.pack(side=tk.LEFT, padx=2)

        udp_var = tk.StringVar(value=udp_val)
        udp_entry = tk.Entry(row_frame, textvariable=udp_var, width=32)
        udp_entry.pack(side=tk.LEFT, padx=2)

        row_data = {
            "frame": row_frame,
            "dir_var": dir_var,
            "tcp_var": tcp_var,
            "udp_var": udp_var,
        }

        del_btn = tk.Button(row_frame, text="X", fg="red", width=3,
                            command=lambda rd=row_data: self._del_mapping_row(rd))
        del_btn.pack(side=tk.LEFT, padx=4)

        self.mapping_rows.append(row_data)

        # Auto-save on changes
        dir_cb.bind("<<ComboboxSelected>>", lambda e: self._sync_and_save())
        tcp_entry.bind("<FocusOut>", lambda e: self._sync_and_save())
        udp_entry.bind("<FocusOut>", lambda e: self._sync_and_save())
        tcp_entry.bind("<Return>", lambda e: self._sync_and_save())
        udp_entry.bind("<Return>", lambda e: self._sync_and_save())

        self._sync_and_save()

    def _del_mapping_row(self, row_data):
        row_data["frame"].destroy()
        self.mapping_rows.remove(row_data)
        self._sync_and_save()

    def _sync_and_save(self):
        """Sync mapping widgets to engine and save config."""
        self.engine.mappings = []
        for r in self.mapping_rows:
            self.engine.mappings.append({
                "direction": r["dir_var"].get(),
                "tcp_value": r["tcp_var"].get(),
                "udp_value": r["udp_var"].get(),
            })
        self._save_config()

    # ---- Connection handlers -----------------------------------------------

    def _tcp_connect(self):
        ip = self.tcp_ip_var.get().strip()
        port = self.tcp_port_var.get().strip()
        if not ip or not port:
            messagebox.showwarning("TCP", "Enter IP and Port.")
            return
        try:
            self.tcp_client.connect(ip, port)
        except ConnectionError as e:
            messagebox.showerror("TCP", str(e))

    def _tcp_disconnect(self):
        self.tcp_client.disconnect()

    def _udp_connect(self):
        ip = self.udp_ip_var.get().strip()
        port = self.udp_port_var.get().strip()
        if not ip or not port:
            messagebox.showwarning("UDP", "Enter IP and Port.")
            return
        try:
            self.udp_socket.connect(ip, port)
        except ConnectionError as e:
            messagebox.showerror("UDP", str(e))

    def _udp_disconnect(self):
        self.udp_socket.disconnect()

    # ---- Status callbacks --------------------------------------------------

    def _on_tcp_status(self, connected):
        if connected:
            self.tcp_status_lbl.config(text="Connected", fg="green")
            self.tcp_conn_btn.config(state=tk.DISABLED)
            self.tcp_disc_btn.config(state=tk.NORMAL)
        else:
            self.tcp_status_lbl.config(text="Disconnected", fg="red")
            self.tcp_conn_btn.config(state=tk.NORMAL)
            self.tcp_disc_btn.config(state=tk.DISABLED)
        self._update_status_bar()

    def _on_udp_status(self, bound):
        if bound:
            self.udp_status_lbl.config(text="Connected", fg="green")
            self.udp_conn_btn.config(state=tk.DISABLED)
            self.udp_disc_btn.config(state=tk.NORMAL)
        else:
            self.udp_status_lbl.config(text="Disconnected", fg="red")
            self.udp_conn_btn.config(state=tk.NORMAL)
            self.udp_disc_btn.config(state=tk.DISABLED)
        self._update_status_bar()

    def _update_status_bar(self):
        tcp_s = "Connected" if self.tcp_client.connected else "Disconnected"
        udp_s = "Bound" if self.udp_socket.bound else "Disconnected"
        self.status_var.set(f"TCP: {tcp_s}  |  UDP: {udp_s}")

    # ---- Data handlers -----------------------------------------------------

    def _on_tcp_data(self, msg):
        self._tcp_log_q.append(f"RX: {msg}")
        # Run through mapping engine
        udp_values = self.engine.process_tcp(msg)
        for uv in udp_values:
            self.udp_socket.send(uv)
            self._udp_log_q.append(f"TX: {uv}")
            self._tcp_log_q.append(f"  -> mapped to UDP: {uv}")

    def _on_udp_data(self, msg):
        self._udp_log_q.append(f"RX: {msg}")
        # Run through mapping engine
        tcp_values = self.engine.process_udp(msg)
        for tv in tcp_values:
            self.tcp_client.send(tv)
            self._tcp_log_q.append(f"TX: {tv}")
            self._udp_log_q.append(f"  -> mapped to TCP: {tv}")

    # ---- Log flushing (throttled) ------------------------------------------

    def _flush_logs(self):
        self._flush_one_log(self.tcp_log, self._tcp_log_q)
        self._flush_one_log(self.udp_log, self._udp_log_q)
        self.after(self.LOG_FLUSH_MS, self._flush_logs)

    @staticmethod
    def _flush_one_log(widget, q):
        if not q:
            return
        widget.config(state=tk.NORMAL)
        while q:
            widget.insert(tk.END, q.popleft() + "\n")
        # Trim to max lines
        line_count = int(widget.index("end-1c").split(".")[0])
        if line_count > BridgeApp.MAX_LOG_LINES:
            widget.delete("1.0", f"{line_count - BridgeApp.MAX_LOG_LINES}.0")
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)

    # ---- Config persistence ------------------------------------------------

    def _save_config(self):
        cfg = {
            "tcp_ip": self.tcp_ip_var.get(),
            "tcp_port": self.tcp_port_var.get(),
            "udp_ip": self.udp_ip_var.get(),
            "udp_port": self.udp_port_var.get(),
            "mappings": self.engine.mappings,
        }
        try:
            with open(get_config_path(), "w") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    def _load_config(self):
        path = get_config_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r") as f:
                cfg = json.load(f)
            self.tcp_ip_var.set(cfg.get("tcp_ip", ""))
            self.tcp_port_var.set(cfg.get("tcp_port", ""))
            self.udp_ip_var.set(cfg.get("udp_ip", ""))
            self.udp_port_var.set(cfg.get("udp_port", ""))
            for m in cfg.get("mappings", []):
                self._add_mapping_row(
                    direction=m.get("direction", "TCP -> UDP"),
                    tcp_val=m.get("tcp_value", ""),
                    udp_val=m.get("udp_value", ""),
                )
        except Exception:
            pass

    # ---- Shutdown ----------------------------------------------------------

    def _on_close(self):
        self._save_config()
        self.tcp_client.disconnect()
        self.udp_socket.disconnect()
        self.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = BridgeApp()
    app.mainloop()

import psutil
import time
import json
import threading
import tkinter as tk
from tkinter import messagebox
import os
import webbrowser

CONFIG_FILE = "config.json"
LOGS_DIR = "logs"
MAX_LOG_FILES = 10  # Mantener solo los últimos 10 logs para no saturar

TECNICO_EMAIL = "tecnico@empresa.cl"
TECNICO_PHONE = "+56912345678"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        config = {
            "period": 60,
            "whitelist": [22, 80, 443, 3389],
            "inactive_threshold": 3,
            "alert_enabled": True
        }
        save_config(config)
        return config
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def rotate_logs():
    files = sorted([f for f in os.listdir(LOGS_DIR) if f.startswith("log_")])
    while len(files) > MAX_LOG_FILES:
        os.remove(os.path.join(LOGS_DIR, files[0]))
        files.pop(0)

class PortScanner:
    def __init__(self, config, alert_callback):
        self.config = config
        self.history = {}  # puerto: scans sin uso
        self.last_log = None
        self.alert_callback = alert_callback
        os.makedirs(LOGS_DIR, exist_ok=True)

    def scan_ports(self):
        conns = psutil.net_connections()
        port_status = {}
        ports_found = set()

        # Puertos en escucha y activos
        for c in conns:
            if c.status == 'LISTEN':
                port = c.laddr.port
                ports_found.add(port)
                self.history[port] = 0
                port_status[port] = "open_active"

        # Contar inactividad
        for port in list(self.history.keys()):
            if port not in ports_found:
                self.history.pop(port)
                continue
            self.history[port] += 1
            if self.history[port] >= self.config["inactive_threshold"]:
                port_status[port] = "open_inactive"

        # Añadir whitelist
        for wport in self.config["whitelist"]:
            if wport not in port_status:
                port_status[wport] = "whitelist"

        timestamp = time.time()
        log = {"timestamp": timestamp, "ports": port_status}
        self.save_log(log)
        self.compare_log(log)
        rotate_logs()
        self.last_log = log

    def save_log(self, log):
        fname = os.path.join(LOGS_DIR, f"log_{int(log['timestamp'])}.json")
        with open(fname, "w") as f:
            json.dump(log, f, indent=4)

    def compare_log(self, new_log):
        if self.last_log is None:
            return
        old_ports = self.last_log["ports"]
        new_ports = new_log["ports"]
        opened = [p for p in new_ports if p not in old_ports and new_ports[p] in ("open_active", "open_inactive")]
        closed = [p for p in old_ports if p not in new_ports]

        if opened:
            print(f"Puertos abiertos nuevos: {opened}")
        if closed:
            print(f"Puertos cerrados: {closed}")

        inactive_ports = [p for p, status in new_ports.items() if status == "open_inactive" and p not in self.config["whitelist"]]
        if inactive_ports and self.config.get("alert_enabled", True):
            self.alert_callback(inactive_ports)

    def close_port(self, port):
        for c in psutil.net_connections():
            if c.laddr and c.laddr.port == port:
                pid = c.pid
                if pid:
                    try:
                        p = psutil.Process(pid)
                        p.terminate()
                        p.wait(timeout=3)
                        print(f"Proceso {pid} cerrado para liberar puerto {port}")
                    except Exception as e:
                        print(f"No se pudo cerrar proceso {pid}: {e}")
                        return False
        time.sleep(2)
        for c in psutil.net_connections():
            if c.laddr and c.laddr.port == port:
                print(f"Puerto {port} sigue activo tras intentar cerrar.")
                return False
        print(f"Puerto {port} cerrado correctamente.")
        return True

def run_scanner(scanner, period):
    while True:
        scanner.scan_ports()
        time.sleep(period)

class App(tk.Tk):
    def __init__(self, scanner, config):
        super().__init__()
        self.scanner = scanner
        self.config_data = config
        self.title("Port Scanner Security App")
        self.geometry("520x450")

        tk.Label(self, text="Periodicidad (segundos)").pack()
        self.period_entry = tk.Entry(self)
        self.period_entry.pack()
        self.period_entry.insert(0, str(self.config_data["period"]))

        tk.Label(self, text="Whitelist (puertos, separados por coma)").pack()
        self.whitelist_entry = tk.Entry(self)
        self.whitelist_entry.pack()
        self.whitelist_entry.insert(0, ",".join(str(p) for p in self.config_data["whitelist"]))

        self.alert_var = tk.BooleanVar(value=self.config_data.get("alert_enabled", True))
        tk.Checkbutton(self, text="Activar alertas para puertos inactivos", variable=self.alert_var).pack()

        tk.Button(self, text="Guardar Configuración", command=self.save_config).pack(pady=10)
        tk.Button(self, text="Abrir carpeta de logs", command=self.open_logs_folder).pack(pady=10)

        # Frame para mostrar puertos inactivos y opción para cerrar
        self.inactive_frame = tk.LabelFrame(self, text="Puertos Inactivos Detectados")
        self.inactive_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.ports_listbox = tk.Listbox(self.inactive_frame)
        self.ports_listbox.pack(fill="both", expand=True, side="left", padx=5, pady=5)

        scrollbar = tk.Scrollbar(self.inactive_frame, orient="vertical")
        scrollbar.config(command=self.ports_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.ports_listbox.config(yscrollcommand=scrollbar.set)

        tk.Button(self, text="Cerrar Puerto Seleccionado", command=self.close_selected_port).pack(pady=5)

    def save_config(self):
        try:
            period = int(self.period_entry.get())
            whitelist = [int(p.strip()) for p in self.whitelist_entry.get().split(",") if p.strip()]
            alert_enabled = self.alert_var.get()

            self.config_data["period"] = period
            self.config_data["whitelist"] = whitelist
            self.config_data["alert_enabled"] = alert_enabled
            save_config(self.config_data)

            messagebox.showinfo("Info", "Configuración guardada. Reinicia la app para aplicar cambios.")
        except Exception as e:
            messagebox.showerror("Error", f"Configuración inválida: {e}")

    def open_logs_folder(self):
        path = os.path.abspath(LOGS_DIR)
        if os.name == 'nt':
            os.startfile(path)
        else:
            webbrowser.open(path)

    def alert_ports(self, ports):
        # Mostrar puertos inactivos en la lista y ventana alerta
        self.ports_listbox.delete(0, tk.END)
        for p in ports:
            self.ports_listbox.insert(tk.END, str(p))
        messagebox.showwarning("Alerta", f"Puertos inactivos detectados:\n{', '.join(str(p) for p in ports)}\n\nPuedes cerrar puertos desde la lista.")

    def close_selected_port(self):
        sel = self.ports_listbox.curselection()
        if not sel:
            messagebox.showinfo("Info", "Selecciona un puerto de la lista primero.")
            return
        port = int(self.ports_listbox.get(sel[0]))

        if port in self.config_data["whitelist"]:
            messagebox.showwarning("Advertencia", f"El puerto {port} está en la whitelist y no será cerrado.")
            return

        confirm = messagebox.askyesno("Confirmar", f"¿Cerrar el proceso que usa el puerto {port}?")
        if confirm:
            success = self.scanner.close_port(port)
            if success:
                messagebox.showinfo("Éxito", f"Puerto {port} cerrado correctamente.")
                self.ports_listbox.delete(sel[0])
            else:
                messagebox.showerror("Error", f"No se pudo cerrar el puerto {port} o sigue activo.")

def main():
    config = load_config()
    app = None

    def alert_callback(ports):
        if app:
            app.alert_ports(ports)

    scanner = PortScanner(config, alert_callback)

    scan_thread = threading.Thread(target=run_scanner, args=(scanner, config["period"]), daemon=True)
    scan_thread.start()

    app = App(scanner, config)
    app.mainloop()

if __name__ == "__main__":
    main()

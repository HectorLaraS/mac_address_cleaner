import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import shutil
import threading
import queue
import time

from help_functions import validate_macs, create_database_copy, remove_endpoint
from APIException import APIException

# =========================
# CONFIG
# =========================
MAX_MACS = 3000
WARN_MACS = 1000
LOG_BATCH = 50
SLEEP_BETWEEN_CALLS = 0.02  # throttle API (20ms)

# =========================
# COLORS
# =========================
COL_BG_MAIN   = "#788089"
COL_PANEL     = "#6f7780"
COL_LABEL_BG  = "#000000"
COL_LABEL_FG  = "#ffffff"
COL_ENTRY_BG  = "#ffffff"
COL_ENTRY_FG  = "#000000"
COL_BTN_EXEC_BG = "#b3202a"
COL_BTN_EXEC_FG = "#000000"
COL_BTN_CLR_BG  = "#f2dc7a"
COL_BTN_CLR_FG  = "#000000"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MAC Address Cleaner")
        self.geometry("980x520")
        self.configure(bg=COL_BG_MAIN)

        self.valid_endpoints = []
        self.file_valid = False
        self.is_running = False
        self.ui_queue = queue.Queue()

        self._build_ui()
        self.after(100, self._drain_ui_queue)

    # =========================
    # UI
    # =========================
    def _build_ui(self):
        panel = tk.Frame(self, bg=COL_PANEL, bd=2, relief="ridge")
        panel.pack(fill="both", expand=True, padx=18, pady=18)

        panel.grid_columnconfigure((0,1,2,3), weight=1)
        panel.grid_rowconfigure(3, weight=1)

        # Username / Password
        self._label(panel, "Username").grid(row=0, column=0, sticky="w", padx=14, pady=6)
        self.ent_user = self._entry(panel)
        self.ent_user.grid(row=0, column=1, sticky="we", padx=10)

        self._label(panel, "Password").grid(row=0, column=2, sticky="w", padx=14, pady=6)
        self.ent_pass = self._entry(panel, show="*")
        self.ent_pass.grid(row=0, column=3, sticky="we", padx=10)

        # File bar + browse
        self.ent_file = self._entry(panel)
        self.ent_file.grid(row=1, column=0, columnspan=3, sticky="we", padx=14, pady=6)

        tk.Button(
            panel, text="Browse (.txt)",
            command=self.browse_txt,
            bg=COL_ENTRY_BG
        ).grid(row=1, column=3, padx=10)

        # Labels
        self._label(panel, "MAC Address to remove").grid(row=2, column=0, columnspan=2, sticky="w", padx=14)
        self._label(panel, "Log File").grid(row=2, column=2, columnspan=2, sticky="w", padx=14)

        # Text areas
        self.txt_mac = tk.Text(panel, bg=COL_ENTRY_BG)
        self.txt_mac.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=14)

        self.txt_log = tk.Text(panel, bg=COL_ENTRY_BG)
        self.txt_log.grid(row=3, column=2, columnspan=2, sticky="nsew", padx=14)

        # Buttons
        self.btn_execute = tk.Button(
            panel, text="Execute (Clear MAC)",
            command=self.on_execute,
            bg=COL_BTN_EXEC_BG, state="disabled"
        )
        self.btn_execute.grid(row=4, column=0, padx=14, pady=10, sticky="w")

        self.btn_clear = tk.Button(
            panel, text="Clear",
            command=self.clear_all,
            bg=COL_BTN_CLR_BG
        )
        self.btn_clear.grid(row=4, column=1, padx=14, pady=10, sticky="w")

    def _label(self, parent, text):
        return tk.Label(parent, text=text, bg=COL_LABEL_BG, fg=COL_LABEL_FG, padx=8)

    def _entry(self, parent, show=None):
        return tk.Entry(parent, bg=COL_ENTRY_BG, show=show or "")

    # =========================
    # FILE LOAD
    # =========================
    def browse_txt(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if not path:
            return

        ok, endpoints = validate_macs(path)
        count = len(endpoints)

        # HARD LIMIT
        if count > MAX_MACS:
            messagebox.showerror(
                "Too many MACs",
                f"Máximo permitido en GUI: {MAX_MACS}\nRecibidos: {count}"
            )
            return

        # WARNING
        if count > WARN_MACS:
            if not messagebox.askyesno(
                "Advertencia",
                f"Se procesarán {count} MACs.\nEsto puede tardar varios minutos.\n\n¿Continuar?"
            ):
                return

        # Copy input file
        dest_dir = Path("./input_files")
        dest_dir.mkdir(exist_ok=True)
        dest = dest_dir / Path(path).name
        shutil.copy2(path, dest)

        self.valid_endpoints = endpoints
        self.file_valid = True

        self.ent_file.delete(0, tk.END)
        self.ent_file.insert(0, str(dest))

        self.txt_mac.delete("1.0", tk.END)
        for e in endpoints:
            self.txt_mac.insert(tk.END, e.replace("%3A", ":") + "\n")

        self.log(f"Archivo cargado: {dest.name} | MACs={count}")
        self._refresh_execute_state()

    # =========================
    # EXECUTION
    # =========================
    def on_execute(self):
        if not messagebox.askyesno("Confirmar", "¿Seguro que deseas borrar las MACs?"):
            return

        self.is_running = True
        self._refresh_execute_state()

        t = threading.Thread(target=self._worker, daemon=True)
        t.start()

    def _worker(self):
        user = self.ent_user.get().strip()
        pwd = self.ent_pass.get().strip()

        try:
            backup = create_database_copy(api_user=user, api_pass=pwd)
            self.ui_queue.put(("log", f"Backup creado: {backup}"))

            removed = not_found = 0
            total = len(self.valid_endpoints)

            for i, ep in enumerate(self.valid_endpoints, start=1):
                api_time, api_user, job, mac, status = remove_endpoint(
                    ep, api_user=user, api_pass=pwd
                )

                if status == 200:
                    removed += 1
                elif status == 404:
                    not_found += 1

                if i % LOG_BATCH == 0 or i == total:
                    self.ui_queue.put((
                        "log",
                        f"Progreso {i}/{total} | Removed={removed} | NotFound={not_found}"
                    ))

                time.sleep(SLEEP_BETWEEN_CALLS)

            self.ui_queue.put(("log", f"FINAL: Removed={removed} | NotFound={not_found}"))
        except Exception as e:
            self.ui_queue.put(("log", f"ERROR: {e}"))
        finally:
            self.ui_queue.put(("done", None))

    # =========================
    # UI QUEUE
    # =========================
    def _drain_ui_queue(self):
        try:
            while True:
                kind, msg = self.ui_queue.get_nowait()
                if kind == "log":
                    self.log(msg)
                elif kind == "done":
                    self.is_running = False
                    self.btn_execute.config(state="disabled")
                    self.log("Proceso terminado. Usa Clear para reiniciar.")
        except queue.Empty:
            pass

        self.after(100, self._drain_ui_queue)

    # =========================
    # HELPERS
    # =========================
    def _refresh_execute_state(self):
        ready = (
            self.file_valid and
            self.ent_user.get().strip() and
            self.ent_pass.get().strip() and
            not self.is_running
        )
        self.btn_execute.config(state="normal" if ready else "disabled")

    def clear_all(self):
        self.ent_user.delete(0, tk.END)
        self.ent_pass.delete(0, tk.END)
        self.ent_file.delete(0, tk.END)
        self.txt_mac.delete("1.0", tk.END)
        self.txt_log.delete("1.0", tk.END)

        self.valid_endpoints.clear()
        self.file_valid = False
        self.is_running = False

        self._refresh_execute_state()

    def log(self, msg):
        self.txt_log.insert(tk.END, msg + "\n")
        self.txt_log.see(tk.END)


if __name__ == "__main__":
    App().mainloop()

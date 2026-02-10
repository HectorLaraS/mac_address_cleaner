import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import shutil

from help_functions import validate_macs, create_database_copy, remove_endpoint
from APIException import APIException

# Paleta similar al mock
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
        self.title("MAC Address Cleaner - ISE")
        self.configure(bg=COL_BG_MAIN)
        self.geometry("980x520")
        self.minsize(900, 480)

        # Estado
        self.file_valid = False
        self.loaded_file_dest: Path | None = None
        self.valid_endpoints: list[str] = []
        self.is_running = False

        self._build_ui()
        self._refresh_execute_state()

    # ---------------- UI ----------------
    def _build_ui(self):
        panel = tk.Frame(self, bg=COL_PANEL, bd=2, relief="ridge")
        panel.pack(fill="both", expand=True, padx=18, pady=18)

        panel.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=1)
        panel.grid_columnconfigure(2, weight=1)
        panel.grid_columnconfigure(3, weight=1)
        panel.grid_rowconfigure(3, weight=1)

        # Username / Password
        self._label(panel, "Username").grid(row=0, column=0, sticky="w", padx=14, pady=(14, 6))
        self.ent_user = self._entry(panel)
        self.ent_user.grid(row=0, column=1, sticky="we", padx=10, pady=(14, 6))
        self.ent_user.bind("<KeyRelease>", lambda e: self._refresh_execute_state())

        self._label(panel, "Password").grid(row=0, column=2, sticky="w", padx=14, pady=(14, 6))
        self.ent_pass = self._entry(panel, show="*")
        self.ent_pass.grid(row=0, column=3, sticky="we", padx=10, pady=(14, 6))
        self.ent_pass.bind("<KeyRelease>", lambda e: self._refresh_execute_state())

        # Barra (ruta) + MAC ADD LIST + Browse
        self.ent_file = self._entry(panel)
        self.ent_file.grid(row=1, column=0, columnspan=3, sticky="we", padx=14, pady=(6, 10), ipady=3)

        right_box = tk.Frame(panel, bg=COL_PANEL)
        right_box.grid(row=1, column=3, sticky="we", padx=10, pady=(6, 10))
        self._label(right_box, "MAC ADD LIST").grid(row=0, column=0, sticky="w", padx=(0, 8))

        btn_browse = tk.Button(
            right_box, text="Browse...",
            command=self.browse_txt,
            bg=COL_ENTRY_BG, fg=COL_ENTRY_FG,
            bd=1, relief="solid", cursor="hand2"
        )
        btn_browse.grid(row=0, column=1, sticky="e")

        # Labels de cajas grandes
        self._label(panel, "MAC Address to remove").grid(row=2, column=0, columnspan=2, sticky="w", padx=14, pady=(4, 6))
        self._label(panel, "Log File").grid(row=2, column=2, columnspan=2, sticky="w", padx=14, pady=(4, 6))

        # Text boxes
        left_frame = tk.Frame(panel, bg=COL_PANEL)
        left_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=14, pady=(0, 10))
        left_frame.grid_rowconfigure(0, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        right_frame = tk.Frame(panel, bg=COL_PANEL)
        right_frame.grid(row=3, column=2, columnspan=2, sticky="nsew", padx=14, pady=(0, 10))
        right_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)

        self.txt_mac_list = tk.Text(left_frame, wrap="none", bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid")
        self.txt_mac_list.grid(row=0, column=0, sticky="nsew")
        self._add_scrollbars(left_frame, self.txt_mac_list)

        self.txt_log = tk.Text(right_frame, wrap="none", bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid")
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        self._add_scrollbars(right_frame, self.txt_log)

        # Botones
        bottom = tk.Frame(panel, bg=COL_PANEL)
        bottom.grid(row=4, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 14))
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=1)

        self.btn_execute = tk.Button(
            bottom, text="Execute (Clear MAC)",
            command=self.on_execute,
            bg=COL_BTN_EXEC_BG, fg=COL_BTN_EXEC_FG,
            bd=1, relief="solid", cursor="hand2",
            width=20, state="disabled"
        )
        self.btn_execute.grid(row=0, column=0, sticky="w", padx=(10, 0), pady=8, ipady=6)

        self.btn_clear = tk.Button(
            bottom, text="Clear",
            command=self.clear_all,
            bg=COL_BTN_CLR_BG, fg=COL_BTN_CLR_FG,
            bd=1, relief="solid", cursor="hand2",
            width=16
        )
        self.btn_clear.grid(row=0, column=1, sticky="w", padx=(40, 0), pady=8, ipady=6)

    def _label(self, parent, text: str) -> tk.Label:
        return tk.Label(
            parent, text=text,
            bg=COL_LABEL_BG, fg=COL_LABEL_FG,
            padx=8, pady=4,
            font=("Segoe UI", 10, "bold")
        )

    def _entry(self, parent, show: str | None = None) -> tk.Entry:
        return tk.Entry(
            parent,
            bg=COL_ENTRY_BG, fg=COL_ENTRY_FG,
            bd=1, relief="solid",
            show=show or ""
        )

    def _add_scrollbars(self, parent: tk.Widget, text_widget: tk.Text) -> None:
        yscroll = tk.Scrollbar(parent, orient="vertical", command=text_widget.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = tk.Scrollbar(parent, orient="horizontal", command=text_widget.xview)
        xscroll.grid(row=1, column=0, sticky="we")
        text_widget.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

    # ------------- State helpers -------------
    def _refresh_execute_state(self):
        user_ok = bool(self.ent_user.get().strip())
        pass_ok = bool(self.ent_pass.get().strip())
        can_run = (self.file_valid and user_ok and pass_ok and (not self.is_running))

        self.btn_execute.configure(state=("normal" if can_run else "disabled"))

    # ---------------- Actions ----------------
    def browse_txt(self):
        path = filedialog.askopenfilename(
            title="Select a TXT file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return

        p = Path(path)
        if p.suffix.lower() != ".txt":
            messagebox.showerror("Invalid file", "Debe de ser un archivo de texto (.txt).")
            return

        # Validar MACs (usa tu lógica validate_macs)
        try:
            ok, endpoints = validate_macs(str(p))
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo validar el archivo.\n{e}")
            return

        if not ok or not endpoints:
            self.file_valid = False
            self.valid_endpoints = []
            self.loaded_file_dest = None
            self._refresh_execute_state()
            messagebox.showerror("Validation failed", "❌ El archivo contiene MACs inválidas. Corrige el TXT.")
            self.log("❌ Validation failed: MACs inválidas.")
            return

        # Guardar copia en ./input_files (requerimiento #1)
        input_dir = Path("./input_files")
        input_dir.mkdir(parents=True, exist_ok=True)
        dest = input_dir / p.name
        shutil.copy2(p, dest)

        # Actualizar estado
        self.file_valid = True
        self.valid_endpoints = endpoints
        self.loaded_file_dest = dest

        # UI: ruta + lista
        self.ent_file.delete(0, tk.END)
        self.ent_file.insert(0, str(dest))

        self.txt_mac_list.delete("1.0", tk.END)
        # endpoints vienen en formato ISE (con %3A). Para mostrar humano: reemplazamos
        for ep in endpoints:
            self.txt_mac_list.insert(tk.END, ep.replace("%3A", ":") + "\n")

        self.log(f"✅ Archivo válido: {p.name} | MACs={len(endpoints)}")
        self.log(f"✅ Copiado a: {dest}")
        self._refresh_execute_state()

    def on_execute(self):
        if self.is_running:
            return

        if not messagebox.askyesno("Confirmación", "¿Estás seguro de ejecutar el borrado de MACs?"):
            return

        # Deshabilitar mientras corre
        self.is_running = True
        self._refresh_execute_state()

        try:
            self.run_clear_mac_process()
        finally:
            # Al terminar: execute deshabilitado hasta Clear (requerimiento #5)
            self.is_running = False
            self.btn_execute.configure(state="disabled")
            self.log("✅ Proceso terminado. 'Execute' quedó deshabilitado. Usa 'Clear' para reiniciar.")
            # NO llamamos _refresh_execute_state() aquí porque quieres que quede disabled

    def run_clear_mac_process(self):
        user = self.ent_user.get().strip()
        pwd = self.ent_pass.get().strip()

        if not self.file_valid or not self.valid_endpoints:
            messagebox.showerror("Missing step", "Primero carga un archivo .txt válido.")
            return

        if not user or not pwd:
            messagebox.showerror("Missing step", "Ingresa Username y Password.")
            return

        # 1) Crear backup de la DB (API snapshot)
        try:
            backup_name = create_database_copy(api_user=user, api_pass=pwd)
            self.log(f"📦 Backup creado: ./backup/{backup_name}")
        except APIException as e:
            self.log(f"❌ Error creando backup: {e}")
            messagebox.showerror("API Error", str(e))
            return
        except Exception as e:
            self.log(f"❌ Error inesperado creando backup: {e}")
            messagebox.showerror("Error", str(e))
            return

        # 2) Remover endpoints uno por uno e imprimir log requerido (#4)
        for endpoint in self.valid_endpoints:
            try:
                api_fetch_time, api_user_used, job_title, mac_format = remove_endpoint(
                    endpoint, api_user=user, api_pass=pwd
                )

                # EXACTO al formato que pediste en la GUI
                self.log(f"{api_fetch_time} | User: {api_user_used} | Detailed Log: {job_title} | Endpoint Removed: {mac_format}")

                self.update_idletasks()

            except APIException as e:
                self.log(f"❌ APIException removiendo {endpoint}: {e}")
            except Exception as e:
                self.log(f"❌ Error removiendo {endpoint}: {e}")

    def clear_all(self):
        # "Reiniciar consola" (estado + UI) para volver a habilitar execute cuando aplique
        self.ent_user.delete(0, tk.END)
        self.ent_pass.delete(0, tk.END)
        self.ent_file.delete(0, tk.END)
        self.txt_mac_list.delete("1.0", tk.END)
        self.txt_log.delete("1.0", tk.END)

        self.file_valid = False
        self.loaded_file_dest = None
        self.valid_endpoints = []
        self.is_running = False

        self._refresh_execute_state()

    def log(self, msg: str):
        self.txt_log.insert(tk.END, msg + "\n")
        self.txt_log.see(tk.END)


if __name__ == "__main__":
    App().mainloop()

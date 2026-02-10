import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path


# -------------------------
# Config de colores (similar a tu paleta)
# -------------------------
COL_BG_MAIN = "#788089"     # gris azulado (fondo)
COL_PANEL   = "#6f7780"     # panel gris
COL_LABEL_BG = "#000000"    # labels negro
COL_LABEL_FG = "#ffffff"    # labels blanco
COL_ENTRY_BG = "#ffffff"
COL_ENTRY_FG = "#000000"

COL_BTN_EXEC_BG = "#b3202a"  # rojo
COL_BTN_EXEC_FG = "#000000"

COL_BTN_CLR_BG = "#f2dc7a"   # amarillo
COL_BTN_CLR_FG = "#000000"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MAC Tool")
        self.configure(bg=COL_BG_MAIN)
        self.geometry("980x520")
        self.minsize(900, 480)

        # Estilo ttk (por si usas ttk widgets)
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Contenedor principal (panel redondeado no existe nativo; simulamos con frame)
        panel = tk.Frame(self, bg=COL_PANEL, bd=2, relief="ridge")
        panel.pack(fill="both", expand=True, padx=18, pady=18)

        # Grid principal
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=1)
        panel.grid_columnconfigure(2, weight=1)
        panel.grid_columnconfigure(3, weight=1)

        # -------------------------
        # Fila 0: Username / Password
        # -------------------------
        self._label(panel, "Username").grid(row=0, column=0, sticky="w", padx=14, pady=(14, 6))
        self.ent_user = self._entry(panel)
        self.ent_user.grid(row=0, column=1, sticky="we", padx=10, pady=(14, 6))

        self._label(panel, "Password").grid(row=0, column=2, sticky="w", padx=14, pady=(14, 6))
        self.ent_pass = self._entry(panel, show="*")
        self.ent_pass.grid(row=0, column=3, sticky="we", padx=10, pady=(14, 6))

        # -------------------------
        # Fila 1: Barra MAC ADD LIST + botón cargar
        # -------------------------
        # Entry grande (ruta)
        self.ent_file = self._entry(panel)
        self.ent_file.grid(row=1, column=0, columnspan=3, sticky="we", padx=14, pady=(6, 10), ipady=3)

        # Label "MAC ADD LIST" + botón browse (la "barra al lado")
        right_box = tk.Frame(panel, bg=COL_PANEL)
        right_box.grid(row=1, column=3, sticky="we", padx=10, pady=(6, 10))
        right_box.grid_columnconfigure(0, weight=1)

        # Label en negro y blanco como pediste
        self._label(right_box, "MAC ADD LIST").grid(row=0, column=0, sticky="w", padx=(0, 8))

        btn_browse = tk.Button(
            right_box,
            text="Browse...",
            command=self.browse_txt,
            bg=COL_ENTRY_BG,
            fg=COL_ENTRY_FG,
            bd=1,
            relief="solid",
            cursor="hand2"
        )
        btn_browse.grid(row=0, column=1, sticky="e")

        # -------------------------
        # Fila 2: Labels de cajas grandes
        # -------------------------
        self._label(panel, "MAC Address to remove").grid(row=2, column=0, columnspan=2, sticky="w", padx=14, pady=(4, 6))
        self._label(panel, "Log File").grid(row=2, column=2, columnspan=2, sticky="w", padx=14, pady=(4, 6))

        # -------------------------
        # Fila 3: Cajas grandes (izq: lista MAC / der: log)
        # -------------------------
        panel.grid_rowconfigure(3, weight=1)

        left_frame = tk.Frame(panel, bg=COL_PANEL)
        left_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=14, pady=(0, 10))
        left_frame.grid_rowconfigure(0, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        right_frame = tk.Frame(panel, bg=COL_PANEL)
        right_frame.grid(row=3, column=2, columnspan=2, sticky="nsew", padx=14, pady=(0, 10))
        right_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)

        # Text izquierda (MAC list)
        self.txt_mac_list = tk.Text(left_frame, wrap="none", bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid")
        self.txt_mac_list.grid(row=0, column=0, sticky="nsew")
        self._add_scrollbars(left_frame, self.txt_mac_list)

        # Text derecha (Log)
        self.txt_log = tk.Text(right_frame, wrap="none", bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid")
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        self._add_scrollbars(right_frame, self.txt_log)

        # -------------------------
        # Fila 4: Botones (Execute / Clear)
        # -------------------------
        bottom = tk.Frame(panel, bg=COL_PANEL)
        bottom.grid(row=4, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 14))
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=1)

        btn_execute = tk.Button(
            bottom,
            text="Execute",
            command=self.execute,
            bg=COL_BTN_EXEC_BG,
            fg=COL_BTN_EXEC_FG,
            bd=1,
            relief="solid",
            cursor="hand2",
            width=16
        )
        btn_execute.grid(row=0, column=0, sticky="w", padx=(10, 0), pady=8, ipady=6)

        btn_clear = tk.Button(
            bottom,
            text="Clear",
            command=self.clear_all,
            bg=COL_BTN_CLR_BG,
            fg=COL_BTN_CLR_FG,
            bd=1,
            relief="solid",
            cursor="hand2",
            width=16
        )
        btn_clear.grid(row=0, column=1, sticky="w", padx=(40, 0), pady=8, ipady=6)

    # -------------------------
    # UI helpers
    # -------------------------
    def _label(self, parent, text: str) -> tk.Label:
        return tk.Label(
            parent,
            text=text,
            bg=COL_LABEL_BG,
            fg=COL_LABEL_FG,
            padx=8,
            pady=4,
            font=("Segoe UI", 10, "bold")
        )

    def _entry(self, parent, show: str | None = None) -> tk.Entry:
        return tk.Entry(
            parent,
            bg=COL_ENTRY_BG,
            fg=COL_ENTRY_FG,
            bd=1,
            relief="solid",
            show=show if show else ""
        )

    def _add_scrollbars(self, parent: tk.Widget, text_widget: tk.Text) -> None:
        # vertical
        yscroll = tk.Scrollbar(parent, orient="vertical", command=text_widget.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        # horizontal
        xscroll = tk.Scrollbar(parent, orient="horizontal", command=text_widget.xview)
        xscroll.grid(row=1, column=0, sticky="we")
        text_widget.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

    # -------------------------
    # Actions
    # -------------------------
    def browse_txt(self) -> None:
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

        try:
            content = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # fallback típico en Windows
            content = p.read_text(encoding="latin-1")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el archivo.\n{e}")
            return

        # Coloca ruta en la barra y carga contenido en el área izquierda
        self.ent_file.delete(0, tk.END)
        self.ent_file.insert(0, str(p))

        self.txt_mac_list.delete("1.0", tk.END)
        self.txt_mac_list.insert("1.0", content)

        self.log(f"Archivo cargado: {p.name} ({len(content)} chars)")

    def clear_all(self) -> None:
        self.ent_user.delete(0, tk.END)
        self.ent_pass.delete(0, tk.END)
        self.ent_file.delete(0, tk.END)
        self.txt_mac_list.delete("1.0", tk.END)
        self.txt_log.delete("1.0", tk.END)

    def execute(self) -> None:
        # Aquí conectas tu lógica real (MSSQL, remoción, etc.)
        user = self.ent_user.get().strip()
        file_path = self.ent_file.get().strip()
        macs_raw = self.txt_mac_list.get("1.0", tk.END).strip()

        self.log("---- EXECUTE ----")
        self.log(f"Username: {user if user else '(vacío)'}")
        self.log(f"File: {file_path if file_path else '(sin archivo)'}")
        self.log(f"MAC ADD LIST chars: {len(macs_raw)}")
        self.log("Aquí iría la lógica de procesamiento...")

    def log(self, msg: str) -> None:
        self.txt_log.insert(tk.END, msg + "\n")
        self.txt_log.see(tk.END)


if __name__ == "__main__":
    App().mainloop()

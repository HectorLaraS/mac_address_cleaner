import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import shutil
import threading
import queue
import time

from help_functions import validate_macs, create_database_copy, remove_endpoint

# =========================
# CONFIG
# =========================
RECOMMENDED_MAX = 3000
ALLOWED_MAX = 5000

WARN_MACS = 1000
SLEEP_BETWEEN_CALLS = 0.02

UI_MAX_LOG_LINES = 2500
DETAIL_EVERY = 1
PROGRESS_UI_EVERY = 5

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


def format_duration(seconds: float) -> str:
    s = int(round(seconds))
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    if h > 0:
        return f"{h}h {m}m {sec}s"
    if m > 0:
        return f"{m}m {sec}s"
    return f"{sec}s"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MAC Address Cleaner")
        self.geometry("980x590")
        self.minsize(920, 520)
        self.configure(bg=COL_BG_MAIN)

        self.valid_endpoints = []
        self.file_valid = False
        self.is_running = False
        self.ui_queue = queue.Queue()

        self.max_limit_var = tk.IntVar(value=RECOMMENDED_MAX)

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_text_var = tk.StringVar(value="0/0")
        self.loaded_text_var = tk.StringVar(value=f"Loaded: 0 | Limit: {RECOMMENDED_MAX}")

        self.run_start_ts = None

        self._build_ui()
        self._refresh_execute_state()
        self.after(100, self._drain_ui_queue)

    # =========================
    # UI
    # =========================
    def _build_ui(self):
        panel = tk.Frame(self, bg=COL_PANEL, bd=2, relief="ridge")
        panel.pack(fill="both", expand=True, padx=18, pady=18)

        panel.grid_columnconfigure((0, 1, 2, 3), weight=1)
        panel.grid_rowconfigure(5, weight=1)

        # Username / Password
        self._label(panel, "Username").grid(row=0, column=0, sticky="w", padx=14, pady=(14, 6))
        self.ent_user = self._entry(panel)
        self.ent_user.grid(row=0, column=1, sticky="we", padx=10, pady=(14, 6))
        self.ent_user.bind("<KeyRelease>", lambda e: self._refresh_execute_state())

        self._label(panel, "Password").grid(row=0, column=2, sticky="w", padx=14, pady=(14, 6))
        self.ent_pass = self._entry(panel, show="*")
        self.ent_pass.grid(row=0, column=3, sticky="we", padx=10, pady=(14, 6))
        self.ent_pass.bind("<KeyRelease>", lambda e: self._refresh_execute_state())

        # Max MAC limit
        limit_row = tk.Frame(panel, bg=COL_PANEL)
        limit_row.grid(row=1, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 6))

        self._label(limit_row, "Max MACs").grid(row=0, column=0, sticky="w", padx=(0, 10))

        opts = [RECOMMENDED_MAX, ALLOWED_MAX]
        self.opt_limit = tk.OptionMenu(limit_row, self.max_limit_var, *opts)
        self.opt_limit.config(bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid")
        self.opt_limit.grid(row=0, column=1, sticky="w")

        tk.Label(
            limit_row,
            textvariable=self.loaded_text_var,
            bg=COL_PANEL,
            fg="black",
            font=("Segoe UI", 9, "bold")
        ).grid(row=0, column=2, sticky="w", padx=(14, 0))

        # File input
        self.ent_file = self._entry(panel)
        self.ent_file.grid(row=2, column=0, columnspan=3, sticky="we", padx=14, pady=(6, 10), ipady=2)

        tk.Button(
            panel,
            text="Browse (.txt)",
            command=self.browse_txt,
            bg=COL_ENTRY_BG,
            bd=1,
            relief="solid",
            width=14
        ).grid(row=2, column=3, padx=10, pady=(6, 10), sticky="e")

        # Progress bar
        prog_row = tk.Frame(panel, bg=COL_PANEL)
        prog_row.grid(row=3, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 10))
        prog_row.grid_columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(
            prog_row,
            orient="horizontal",
            mode="determinate",
            maximum=100.0,
            variable=self.progress_var
        )
        self.progress.grid(row=0, column=0, sticky="we", padx=(0, 12))

        tk.Label(
            prog_row,
            textvariable=self.progress_text_var,
            bg=COL_PANEL,
            font=("Segoe UI", 10, "bold"),
            width=10
        ).grid(row=0, column=1)

        # Labels
        self._label(panel, "MAC Addresses to Remove").grid(row=4, column=0, columnspan=2, sticky="w", padx=14)
        self._label(panel, "Log Output").grid(row=4, column=2, columnspan=2, sticky="w", padx=14)

        # Text areas
        self.txt_mac = tk.Text(panel, bg=COL_ENTRY_BG, bd=1, relief="solid")
        self.txt_mac.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=14, pady=(0, 12))

        self.txt_log = tk.Text(panel, bg=COL_ENTRY_BG, bd=1, relief="solid")
        self.txt_log.grid(row=5, column=2, columnspan=2, sticky="nsew", padx=14, pady=(0, 12))

        # Buttons
        bottom = tk.Frame(panel, bg=COL_PANEL)
        bottom.grid(row=6, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 14))

        self.btn_execute = tk.Button(
            bottom,
            text="Execute (Clear MACs)",
            command=self.on_execute,
            bg=COL_BTN_EXEC_BG,
            width=20,
            state="disabled"
        )
        self.btn_execute.grid(row=0, column=0, padx=(10, 30), pady=8)

        self.btn_clear = tk.Button(
            bottom,
            text="Clear / Reset",
            command=self.clear_all,
            bg=COL_BTN_CLR_BG,
            width=20
        )
        self.btn_clear.grid(row=0, column=1, pady=8)

    def _label(self, parent, text):
        return tk.Label(parent, text=text, bg=COL_LABEL_BG, fg=COL_LABEL_FG, padx=8, pady=4)

    def _entry(self, parent, show=None):
        return tk.Entry(parent, bg=COL_ENTRY_BG, bd=1, relief="solid", show=show or "")

    # =========================
    # FILE LOAD + VALIDATION
    # =========================
    def browse_txt(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if not path:
            return

        ok, endpoints, errors = validate_macs(path)

        if not ok:
            MAX_SHOW = 8
            preview = errors[:MAX_SHOW]

            lines = [
                f"Line {ln}: '{val}' -> {reason}"
                for ln, val, reason in preview
            ]

            more = ""
            if len(errors) > MAX_SHOW:
                more = f"\n(+{len(errors) - MAX_SHOW} more errors not shown)"

            messagebox.showerror(
                "Validation Failed",
                "The file contains invalid MAC addresses.\n\n"
                "Fix the following lines:\n\n"
                + "\n".join(lines)
                + more
            )
            return

        count = len(endpoints)
        chosen_limit = int(self.max_limit_var.get())

        if count > chosen_limit:
            messagebox.showerror(
                "Too Many MACs",
                f"This file contains {count} MACs.\n"
                f"Selected limit: {chosen_limit}."
            )
            return

        if chosen_limit == ALLOWED_MAX:
            if not messagebox.askyesno(
                "Warning",
                "You selected the 5000 limit.\nThis may take longer.\n\nContinue?"
            ):
                return

        if count > WARN_MACS:
            if not messagebox.askyesno(
                "Warning",
                f"This run will process {count} MACs.\n\nContinue?"
            ):
                return

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

        self.loaded_text_var.set(f"Loaded: {count} | Limit: {chosen_limit}")
        self._set_progress(0, count)
        self.log(f"File loaded: {dest.name} | MACs={count}")

        self._refresh_execute_state()

    # =========================
    # EXECUTION
    # =========================
    def on_execute(self):
        if not messagebox.askyesno("Confirm", "Are you sure you want to clear these MACs?"):
            return

        self.is_running = True
        self.run_start_ts = time.perf_counter()
        self._refresh_execute_state()
        self.log("Starting job...")

        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        removed = 0
        not_found = 0
        total = len(self.valid_endpoints)

        try:
            backup = create_database_copy()
            self.ui_queue.put(("log", f"Backup created: {backup}"))

            for i, ep in enumerate(self.valid_endpoints, start=1):
                api_time, api_user, job, mac, status = remove_endpoint(ep)

                if status == 200:
                    removed += 1
                    result = "REMOVED"
                else:
                    not_found += 1
                    result = "NOT FOUND"

                self.ui_queue.put(("log", f"[{i}/{total}] {mac} -> {result}"))
                percent = (i / total) * 100.0
                self.ui_queue.put(("progress", (percent, i, total)))

                time.sleep(SLEEP_BETWEEN_CALLS)

            self.ui_queue.put(("log", f"DONE: Removed={removed} | NotFound={not_found}"))

        except Exception as e:
            self.ui_queue.put(("log", f"ERROR: {e}"))
        finally:
            elapsed = time.perf_counter() - self.run_start_ts
            self.ui_queue.put(("elapsed", elapsed))
            self.ui_queue.put(("done", None))

    # =========================
    # UI QUEUE
    # =========================
    def _drain_ui_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()

                if kind == "log":
                    self.log(payload)
                elif kind == "progress":
                    p, i, t = payload
                    self.progress_var.set(p)
                    self.progress_text_var.set(f"{i}/{t}")
                elif kind == "elapsed":
                    self.log(f"Total time: {format_duration(payload)}")
                elif kind == "done":
                    self.is_running = False
                    self.btn_execute.config(state="disabled")
                    self.log("Job finished. Click Clear / Reset to start again.")
        except queue.Empty:
            pass

        self.after(100, self._drain_ui_queue)

    # =========================
    # HELPERS
    # =========================
    def _refresh_execute_state(self):
        ready = self.file_valid and not self.is_running
        self.btn_execute.config(state="normal" if ready else "disabled")

    def _set_progress(self, i: int, total: int):
        if total > 0:
            self.progress_var.set((i / total) * 100.0)
            self.progress_text_var.set(f"{i}/{total}")

    def clear_all(self):
        self.ent_user.delete(0, tk.END)
        self.ent_pass.delete(0, tk.END)
        self.ent_file.delete(0, tk.END)
        self.txt_mac.delete("1.0", tk.END)
        self.txt_log.delete("1.0", tk.END)

        self.valid_endpoints.clear()
        self.file_valid = False
        self.is_running = False
        self.run_start_ts = None

        limit = int(self.max_limit_var.get())
        self.loaded_text_var.set(f"Loaded: 0 | Limit: {limit}")
        self._set_progress(0, 0)
        self._refresh_execute_state()

    def log(self, msg: str):
        self.txt_log.insert(tk.END, msg + "\n")

        lines = int(self.txt_log.index("end-1c").split(".")[0])
        if lines > UI_MAX_LOG_LINES:
            self.txt_log.delete("1.0", f"{lines - UI_MAX_LOG_LINES}.0")

        self.txt_log.see(tk.END)


if __name__ == "__main__":
    App().mainloop()

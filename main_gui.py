import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import shutil
import threading
import queue
import time
import os
import csv
from datetime import datetime

from help_functions import validate_macs, create_database_copy, remove_endpoint
from APIException import APIException

# =========================
# CONFIG
# =========================
RECOMMENDED_MAX = 3000
ALLOWED_MAX = 5000
WARN_MACS = 1000

UI_MAX_LOG_LINES = 2500
DETAIL_EVERY = 1
PROGRESS_UI_EVERY = 5

RATE_PROFILES = {
    "Fast": 0.00,
    "Balanced": 0.02,
    "Safe": 0.08,
}

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
COL_BTN_CANCEL_BG = "#e0e0e0"
COL_BTN_CANCEL_FG = "#000000"


def format_duration(seconds: float) -> str:
    s = max(0, int(round(seconds)))
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    if h > 0:
        return f"{h}h {m}m {sec}s"
    if m > 0:
        return f"{m}m {sec}s"
    return f"{sec}s"


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_open_folder(path: str) -> None:
    try:
        os.startfile(os.path.abspath(path))  # Windows
    except Exception:
        try:
            os.system(f'explorer "{os.path.abspath(path)}"')
        except Exception:
            pass


def append_run_log(job_log_name: str, line: str) -> None:
    if not job_log_name:
        return
    os.makedirs("./jobs_executed", exist_ok=True)
    path = os.path.join("./jobs_executed", job_log_name)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def is_auth_error(msg: str) -> bool:
    m = (msg or "").lower()
    return ("401" in m) or ("authentication failed" in m)


def is_forbidden_error(msg: str) -> bool:
    m = (msg or "").lower()
    return ("403" in m) or ("forbidden" in m) or ("authorization failed" in m)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MAC Address Cleaner")
        self.geometry("1020x650")
        self.minsize(940, 580)
        self.configure(bg=COL_BG_MAIN)

        self.valid_endpoints: list[str] = []
        self.file_valid = False
        self.is_running = False
        self.ui_queue = queue.Queue()
        self.cancel_event = threading.Event()

        self.max_limit_var = tk.IntVar(value=RECOMMENDED_MAX)
        self.unique_only_var = tk.BooleanVar(value=True)
        self.rate_profile_var = tk.StringVar(value="Balanced")

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_text_var = tk.StringVar(value="0/0")
        self.eta_text_var = tk.StringVar(value="ETA: --")
        self.loaded_text_var = tk.StringVar(value=f"Loaded: 0 | Limit: {RECOMMENDED_MAX}")

        self.run_start_ts: float | None = None

        self.run_job_log_name: str | None = None
        self.run_job_start_time: datetime | None = None

        self.report_dir = Path("./reports")
        self.report_dir.mkdir(exist_ok=True)
        self.last_removed_report: Path | None = None
        self.last_summary_report: Path | None = None

        self.run_results: list[dict] = []

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
        panel.grid_rowconfigure(6, weight=1)

        self._label(panel, "Username").grid(row=0, column=0, sticky="w", padx=14, pady=(14, 6))
        self.ent_user = self._entry(panel)
        self.ent_user.grid(row=0, column=1, sticky="we", padx=10, pady=(14, 6))
        self.ent_user.bind("<KeyRelease>", lambda e: self._refresh_execute_state())

        self._label(panel, "Password").grid(row=0, column=2, sticky="w", padx=14, pady=(14, 6))
        self.ent_pass = self._entry(panel, show="*")
        self.ent_pass.grid(row=0, column=3, sticky="we", padx=10, pady=(14, 6))
        self.ent_pass.bind("<KeyRelease>", lambda e: self._refresh_execute_state())

        opt_row = tk.Frame(panel, bg=COL_PANEL)
        opt_row.grid(row=1, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 8))
        opt_row.grid_columnconfigure(6, weight=1)

        self._label(opt_row, "Max MACs").grid(row=0, column=0, sticky="w", padx=(0, 10))
        opts = [RECOMMENDED_MAX, ALLOWED_MAX]
        self.opt_limit = tk.OptionMenu(opt_row, self.max_limit_var, *opts)
        self.opt_limit.config(bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid", highlightthickness=0)
        self.opt_limit.grid(row=0, column=1, sticky="w")

        tk.Checkbutton(
            opt_row,
            text="Unique only",
            variable=self.unique_only_var,
            bg=COL_PANEL,
            fg="black",
            activebackground=COL_PANEL
        ).grid(row=0, column=2, sticky="w", padx=(16, 0))

        self._label(opt_row, "Rate").grid(row=0, column=3, sticky="w", padx=(16, 10))
        self.opt_rate = tk.OptionMenu(opt_row, self.rate_profile_var, *RATE_PROFILES.keys())
        self.opt_rate.config(bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid", highlightthickness=0)
        self.opt_rate.grid(row=0, column=4, sticky="w")

        tk.Label(
            opt_row,
            textvariable=self.loaded_text_var,
            bg=COL_PANEL,
            fg="black",
            font=("Segoe UI", 9, "bold")
        ).grid(row=0, column=6, sticky="w", padx=(16, 0))

        self.ent_file = self._entry(panel)
        self.ent_file.grid(row=2, column=0, columnspan=3, sticky="we", padx=14, pady=(6, 10), ipady=2)

        tk.Button(
            panel,
            text="Browse (.txt)",
            command=self.browse_txt,
            bg=COL_ENTRY_BG, fg=COL_ENTRY_FG,
            bd=1, relief="solid",
            cursor="hand2",
            width=14
        ).grid(row=2, column=3, padx=10, pady=(6, 10), sticky="e")

        prog_row = tk.Frame(panel, bg=COL_PANEL)
        prog_row.grid(row=3, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 10))
        prog_row.grid_columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(
            prog_row, orient="horizontal", mode="determinate",
            maximum=100.0, variable=self.progress_var
        )
        self.progress.grid(row=0, column=0, sticky="we", padx=(0, 12))

        tk.Label(
            prog_row, textvariable=self.progress_text_var,
            bg=COL_PANEL, fg="black",
            font=("Segoe UI", 10, "bold"), width=10
        ).grid(row=0, column=1, sticky="e")

        tk.Label(
            prog_row, textvariable=self.eta_text_var,
            bg=COL_PANEL, fg="black",
            font=("Segoe UI", 10), width=16
        ).grid(row=0, column=2, sticky="e", padx=(12, 0))

        self._label(panel, "MAC Addresses to Remove").grid(row=4, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 6))
        self._label(panel, "Log Output").grid(row=4, column=2, columnspan=2, sticky="w", padx=14, pady=(2, 6))

        self.txt_mac = tk.Text(panel, bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid", wrap="none")
        self.txt_mac.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=14, pady=(0, 12))

        self.txt_log = tk.Text(panel, bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid", wrap="none")
        self.txt_log.grid(row=5, column=2, columnspan=2, sticky="nsew", padx=14, pady=(0, 12))
        panel.grid_rowconfigure(5, weight=1)

        bottom = tk.Frame(panel, bg=COL_PANEL)
        bottom.grid(row=7, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 10))
        bottom.grid_columnconfigure((0, 1, 2, 3), weight=1)

        btn_w = 20
        btn_ipady = 6

        self.btn_execute = tk.Button(
            bottom, text="Execute (Clear MACs)",
            command=self.on_execute,
            bg=COL_BTN_EXEC_BG, fg=COL_BTN_EXEC_FG,
            bd=1, relief="solid", cursor="hand2",
            width=btn_w, state="disabled"
        )
        self.btn_execute.grid(row=0, column=0, sticky="w", padx=(10, 10), pady=8, ipady=btn_ipady)

        self.btn_cancel = tk.Button(
            bottom, text="Cancel",
            command=self.on_cancel,
            bg=COL_BTN_CANCEL_BG, fg=COL_BTN_CANCEL_FG,
            bd=1, relief="solid", cursor="hand2",
            width=btn_w, state="disabled"
        )
        self.btn_cancel.grid(row=0, column=1, sticky="w", padx=(10, 10), pady=8, ipady=btn_ipady)

        self.btn_save_removed = tk.Button(
            bottom, text="Save Removed MACs...",
            command=self.save_removed_macs,
            bg=COL_ENTRY_BG, fg=COL_ENTRY_FG,
            bd=1, relief="solid", cursor="hand2",
            width=btn_w, state="disabled"
        )
        self.btn_save_removed.grid(row=0, column=2, sticky="w", padx=(10, 10), pady=8, ipady=btn_ipady)

        self.btn_open_reports = tk.Button(
            bottom, text="Open Reports Folder",
            command=self.open_reports_folder,
            bg=COL_ENTRY_BG, fg=COL_ENTRY_FG,
            bd=1, relief="solid", cursor="hand2",
            width=btn_w
        )
        self.btn_open_reports.grid(row=0, column=3, sticky="w", padx=(10, 0), pady=8, ipady=btn_ipady)

        bottom2 = tk.Frame(panel, bg=COL_PANEL)
        bottom2.grid(row=8, column=0, columnspan=4, sticky="we", padx=14, pady=(0, 14))
        self.btn_clear = tk.Button(
            bottom2, text="Clear / Reset",
            command=self.clear_all,
            bg=COL_BTN_CLR_BG, fg=COL_BTN_CLR_FG,
            bd=1, relief="solid", cursor="hand2",
            width=btn_w
        )
        self.btn_clear.pack(side="left", padx=(10, 0), pady=6, ipady=btn_ipady)

    def _label(self, parent, text):
        return tk.Label(parent, text=text, bg=COL_LABEL_BG, fg=COL_LABEL_FG,
                        padx=8, pady=4, font=("Segoe UI", 10, "bold"))

    def _entry(self, parent, show=None):
        return tk.Entry(parent, bg=COL_ENTRY_BG, fg=COL_ENTRY_FG, bd=1, relief="solid", show=show or "")

    # =========================
    # FILE LOAD + VALIDATION
    # =========================
    def browse_txt(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if not path:
            return

        ok, endpoints, errors = validate_macs(path)
        if not ok:
            self._show_validation_errors(errors)
            return

        skipped = 0
        if self.unique_only_var.get():
            seen = set()
            unique = []
            for ep in endpoints:
                if ep not in seen:
                    seen.add(ep)
                    unique.append(ep)
            skipped = len(endpoints) - len(unique)
            endpoints = unique

        count = len(endpoints)
        chosen_limit = int(self.max_limit_var.get())

        if count > chosen_limit:
            messagebox.showerror(
                "Too Many MACs",
                f"This file contains {count} valid MACs.\nSelected limit: {chosen_limit}.\n\nReduce the file or change the limit."
            )
            return

        if chosen_limit == ALLOWED_MAX:
            if not messagebox.askyesno(
                "Warning",
                "You selected the 5000 limit.\nThis may take longer and ISE may rate-limit.\n\nContinue?"
            ):
                return

        if count > WARN_MACS:
            if not messagebox.askyesno(
                "Warning",
                f"This run will process {count} MACs.\nIt may take several minutes.\n\nContinue?"
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
        self.eta_text_var.set("ETA: --")

        self.log(f"✅ File loaded: {dest.name} | MACs={count} | UniqueOnly={self.unique_only_var.get()}")
        if skipped:
            self.log(f"ℹ️ Duplicates removed: {skipped}")

        self.btn_save_removed.config(state="disabled")
        self._refresh_execute_state()

    def _show_validation_errors(self, errors):
        MAX_SHOW = 10
        preview = errors[:MAX_SHOW]
        lines = [f"Line {ln}: '{val}' -> {reason}" for ln, val, reason in preview]
        more = f"\n(+{len(errors) - MAX_SHOW} more)" if len(errors) > MAX_SHOW else ""

        messagebox.showerror(
            "Validation Failed",
            "The file contains invalid MAC addresses.\n\nFix these lines and try again:\n\n" +
            "\n".join(lines) + more
        )

    # =========================
    # EXECUTION
    # =========================
    def on_execute(self):
        if not messagebox.askyesno("Confirm", "Are you sure you want to clear these MACs?"):
            return

        self.is_running = True
        self.cancel_event.clear()
        self.run_results = []

        self.run_start_ts = time.perf_counter()
        self.run_job_start_time = datetime.now()

        api_user = self.ent_user.get().strip()
        stamp = now_stamp()
        self.run_job_log_name = f"job_{stamp}_{api_user}.log"

        self._refresh_execute_state()
        self.btn_cancel.config(state="normal")
        self.btn_save_removed.config(state="disabled")

        append_run_log(self.run_job_log_name, "==================== JOB START ====================")
        append_run_log(self.run_job_log_name, f"Start time: {self.run_job_start_time}")
        append_run_log(self.run_job_log_name, f"User: {api_user}")
        append_run_log(self.run_job_log_name, f"Input file: {self.ent_file.get().strip()}")
        append_run_log(self.run_job_log_name, f"Total MACs: {len(self.valid_endpoints)}")
        append_run_log(self.run_job_log_name, f"Unique only: {self.unique_only_var.get()}")
        append_run_log(self.run_job_log_name, f"Rate profile: {self.rate_profile_var.get()} (sleep={RATE_PROFILES[self.rate_profile_var.get()]}s)")
        append_run_log(self.run_job_log_name, "--------------------------------------------------")

        self.log("▶ Job started...")
        self.log(f"Run log: ./jobs_executed/{self.run_job_log_name}")

        threading.Thread(target=self._worker, daemon=True).start()

    def on_cancel(self):
        if not self.is_running:
            return
        if messagebox.askyesno("Cancel", "Cancel the current run? A partial report will be generated."):
            self.cancel_event.set()
            self.btn_cancel.config(state="disabled")
            self.log("⛔ Cancel requested...")
            append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | CANCEL_REQUESTED")

    def _worker(self):
        user = self.ent_user.get().strip()
        pwd = self.ent_pass.get().strip()

        removed = 0
        not_found = 0
        errors_count = 0
        total = len(self.valid_endpoints)

        sleep_s = RATE_PROFILES.get(self.rate_profile_var.get(), 0.02)
        t_loop_start = time.perf_counter()

        stamp = now_stamp()
        removed_report = self.report_dir / f"removed_{stamp}.txt"
        summary_report = self.report_dir / f"summary_{stamp}.csv"
        self.last_removed_report = removed_report
        self.last_summary_report = summary_report

        # ---------- AUTH CHECK / BACKUP (ONE REQUEST TO FAIL FAST) ----------
        try:
            backup = create_database_copy(api_user=user, api_pass=pwd)
            self.ui_queue.put(("log", f"📦 Backup created: {backup}"))
            append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | BACKUP | {backup}")
        except Exception as e:
            err = str(e)
            append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | BACKUP_FAILED | {err}")

            if is_auth_error(err):
                self.ui_queue.put(("fatal_reset", {
                    "title": "Authentication Failed (401)",
                    "message": (
                        "The credentials you entered are invalid.\n\n"
                        "The operation was stopped and the application was reset.\n"
                        "Please verify your username/password and try again."
                    )
                }))
            elif is_forbidden_error(err):
                self.ui_queue.put(("fatal_reset", {
                    "title": "Forbidden (403)",
                    "message": (
                        "Your account does not have permission to perform this operation (403).\n\n"
                        "The operation was stopped and the application was reset.\n"
                        "Please request the proper ISE API permissions and try again."
                    )
                }))
            else:
                self.ui_queue.put(("fatal_reset", {
                    "title": "Backup Failed",
                    "message": (
                        "Could not create the backup before deleting MACs.\n\n"
                        f"Error: {err}\n\n"
                        "The operation was stopped and the application was reset."
                    )
                }))
            return  # IMPORTANT: stop here (no DELETE requests)

        # ---------- MAIN LOOP ----------
        try:
            for i, ep in enumerate(self.valid_endpoints, start=1):
                if self.cancel_event.is_set():
                    self.ui_queue.put(("log", "⛔ Run cancelled by user. Generating partial reports..."))
                    append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | CANCELLED")
                    break

                try:
                    api_time, api_user_used, job_log_name, mac, status = remove_endpoint(
                        ep,
                        api_user=user,
                        api_pass=pwd,
                        job_log_name=self.run_job_log_name or ""
                    )

                    if status == 200:
                        removed += 1
                        result = "REMOVED"
                    elif status == 404:
                        not_found += 1
                        result = "NOT_FOUND"
                    else:
                        errors_count += 1
                        result = f"STATUS_{status}"

                    self.run_results.append({
                        "timestamp": str(api_time),
                        "mac": mac,
                        "result": result,
                        "job_log": job_log_name,
                        "user": api_user_used,
                        "status": status,
                    })

                    if DETAIL_EVERY == 1 or (i % DETAIL_EVERY == 0) or (i == total):
                        self.ui_queue.put(("log", f"[{i}/{total}] {mac} -> {result}"))

                except APIException as ae:
                    err = str(ae)
                    append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | API_ERROR | {err}")

                    # Fail fast on 401/403 (do not spam API)
                    if is_auth_error(err):
                        self.ui_queue.put(("fatal_reset", {
                            "title": "Authentication Failed (401)",
                            "message": (
                                "Authentication failed during the deletion process.\n\n"
                                "The operation was stopped and the application was reset."
                            )
                        }))
                        return
                    if is_forbidden_error(err):
                        self.ui_queue.put(("fatal_reset", {
                            "title": "Forbidden (403)",
                            "message": (
                                "Authorization failed (403) during the deletion process.\n\n"
                                "The operation was stopped and the application was reset."
                            )
                        }))
                        return

                    # Otherwise count as error and continue
                    errors_count += 1
                    mac_colon = ep.replace("%3A", ":")
                    self.run_results.append({
                        "timestamp": str(datetime.now()),
                        "mac": mac_colon,
                        "result": "ERROR_APIEXCEPTION",
                        "job_log": self.run_job_log_name or "",
                        "user": user,
                        "status": -1,
                        "error": err,
                    })
                    self.ui_queue.put(("log", f"[{i}/{total}] {mac_colon} -> ERROR ({err})"))

                except Exception as e:
                    errors_count += 1
                    mac_colon = ep.replace("%3A", ":")
                    self.run_results.append({
                        "timestamp": str(datetime.now()),
                        "mac": mac_colon,
                        "result": "ERROR_EXCEPTION",
                        "job_log": self.run_job_log_name or "",
                        "user": user,
                        "status": -1,
                        "error": str(e),
                    })
                    self.ui_queue.put(("log", f"[{i}/{total}] {mac_colon} -> ERROR_EXCEPTION ({e})"))
                    append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | ERROR_EXCEPTION | {mac_colon} | {e}")

                if i % PROGRESS_UI_EVERY == 0 or i == total:
                    elapsed = time.perf_counter() - t_loop_start
                    avg = elapsed / max(1, i)
                    remaining = (total - i) * avg
                    percent = (i / total) * 100.0 if total else 0.0
                    self.ui_queue.put(("progress", (percent, i, total, remaining)))

                if i % 50 == 0 or i == total:
                    self.ui_queue.put(("log", f"Progress: {i}/{total} | Removed={removed} | NotFound={not_found} | Errors={errors_count}"))
                    append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | SUMMARY | i={i}/{total} removed={removed} not_found={not_found} errors={errors_count}")

                if sleep_s > 0:
                    time.sleep(sleep_s)

            self._write_reports(removed_report, summary_report)
            self.ui_queue.put(("log", f"✅ Reports generated: {removed_report.name}, {summary_report.name}"))
            self.ui_queue.put(("reports_ready", None))

            processed = len(self.run_results)
            self.ui_queue.put(("log", f"✅ DONE: Processed={processed} | Removed={removed} | NotFound={not_found} | Errors={errors_count}"))

        except Exception as e:
            self.ui_queue.put(("log", f"❌ FATAL ERROR: {e}"))
            append_run_log(self.run_job_log_name or "", f"{datetime.now().isoformat()} | FATAL_ERROR | {e}")

        finally:
            end_ts = time.perf_counter()
            start_ts = self.run_start_ts or end_ts
            elapsed_total = end_ts - start_ts
            self.ui_queue.put(("elapsed", elapsed_total))

            end_dt = datetime.now()
            append_run_log(self.run_job_log_name or "", "--------------------------------------------------")
            append_run_log(self.run_job_log_name or "", "==================== JOB SUMMARY ==================")
            append_run_log(self.run_job_log_name or "", f"End time: {end_dt}")
            append_run_log(self.run_job_log_name or "", f"Duration: {format_duration(elapsed_total)} ({elapsed_total:.2f}s)")
            append_run_log(self.run_job_log_name or "", f"Totals: processed={len(self.run_results)} removed={removed} not_found={not_found} errors={errors_count}")
            append_run_log(self.run_job_log_name or "", f"Rate profile: {self.rate_profile_var.get()} (sleep={RATE_PROFILES[self.rate_profile_var.get()]}s)")
            append_run_log(self.run_job_log_name or "", f"Reports: {removed_report.name}, {summary_report.name}")
            append_run_log(self.run_job_log_name or "", "===================== JOB END =====================")

            self.ui_queue.put(("done", None))

    def _write_reports(self, removed_report: Path, summary_report: Path) -> None:
        removed_only = [r["mac"] for r in self.run_results if r.get("result") == "REMOVED"]
        with open(removed_report, "w", encoding="utf-8") as f:
            for mac in removed_only:
                f.write(mac + "\n")

        with open(summary_report, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["timestamp", "user", "mac", "result", "status", "job_log", "error"]
            )
            writer.writeheader()
            for r in self.run_results:
                writer.writerow({
                    "timestamp": r.get("timestamp", ""),
                    "user": r.get("user", ""),
                    "mac": r.get("mac", ""),
                    "result": r.get("result", ""),
                    "status": r.get("status", ""),
                    "job_log": r.get("job_log", ""),
                    "error": r.get("error", ""),
                })

    # =========================
    # REPORT BUTTONS
    # =========================
    def save_removed_macs(self):
        if not self.last_removed_report or not self.last_removed_report.exists():
            messagebox.showinfo("No report", "No removed MACs report is available yet.")
            return

        dest = filedialog.asksaveasfilename(
            title="Save Removed MACs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=self.last_removed_report.name
        )
        if not dest:
            return

        shutil.copy2(self.last_removed_report, dest)
        self.log(f"💾 Removed MACs saved to: {dest}")

    def open_reports_folder(self):
        self.report_dir.mkdir(exist_ok=True)
        safe_open_folder(str(self.report_dir))

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
                    percent, i, total, remaining = payload
                    self.progress_var.set(percent)
                    self.progress_text_var.set(f"{i}/{total}")
                    self.eta_text_var.set(f"ETA: {format_duration(remaining)}")

                elif kind == "reports_ready":
                    self.btn_save_removed.config(state="normal")

                elif kind == "elapsed":
                    elapsed = float(payload)
                    self.log(f"⏱ Total time: {format_duration(elapsed)} ({elapsed:.2f}s)")

                elif kind == "fatal_reset":
                    title = payload.get("title", "Error")
                    msg = payload.get("message", "An error occurred.")
                    # Show message, then reset GUI
                    messagebox.showerror(title, msg)
                    self.clear_all()

                elif kind == "done":
                    self.is_running = False
                    self.btn_execute.config(state="disabled")  # must reset per your rule
                    self.btn_cancel.config(state="disabled")
                    self.log("Job finished. Click 'Clear / Reset' to start a new run.")
        except queue.Empty:
            pass

        self.after(100, self._drain_ui_queue)

    # =========================
    # HELPERS
    # =========================
    def _refresh_execute_state(self):
        ready = (
            self.file_valid and
            bool(self.ent_user.get().strip()) and
            bool(self.ent_pass.get().strip()) and
            not self.is_running
        )
        self.btn_execute.config(state="normal" if ready else "disabled")

    def _set_progress(self, i: int, total: int):
        if total <= 0:
            self.progress_var.set(0.0)
            self.progress_text_var.set("0/0")
            self.eta_text_var.set("ETA: --")
            return
        self.progress_var.set((i / total) * 100.0)
        self.progress_text_var.set(f"{i}/{total}")
        self.eta_text_var.set("ETA: --")

    def clear_all(self):
        self.ent_user.delete(0, tk.END)
        self.ent_pass.delete(0, tk.END)
        self.ent_file.delete(0, tk.END)
        self.txt_mac.delete("1.0", tk.END)
        self.txt_log.delete("1.0", tk.END)

        self.valid_endpoints.clear()
        self.file_valid = False
        self.is_running = False
        self.cancel_event.clear()
        self.run_start_ts = None

        self.run_job_log_name = None
        self.run_job_start_time = None
        self.run_results = []

        chosen_limit = int(self.max_limit_var.get())
        self.loaded_text_var.set(f"Loaded: 0 | Limit: {chosen_limit}")
        self._set_progress(0, 0)

        self.btn_cancel.config(state="disabled")
        self.btn_save_removed.config(state="disabled")

        self._refresh_execute_state()

    def log(self, msg: str):
        self.txt_log.insert(tk.END, msg + "\n")

        lines = int(self.txt_log.index("end-1c").split(".")[0])
        if lines > UI_MAX_LOG_LINES:
            self.txt_log.delete("1.0", f"{lines - UI_MAX_LOG_LINES}.0")

        self.txt_log.see(tk.END)


if __name__ == "__main__":
    App().mainloop()

# =============================================================================
#  whitelist_manager.py
#  GUI for managing the Pyranoid Signal whitelist.
#
#  Run this before running pyranoid_signal.py if youre not multi terminal.
#  The monitor picks up any saves automatically via hot-reload.
#
#  No extra dependencies — uses only Python standard-library tkinter.
# =============================================================================

import os
import csv
import glob
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Must stay in sync with the value in trusted_port_monitor.py
SCRIPT_DIR    = Path(__file__).parent
WHITELIST_FILE = SCRIPT_DIR / "whitelist.txt"
LOG_DIR        = SCRIPT_DIR / "tpm_logs"

# =============================================================================
#  COLOUR PALETTE  (dark, matching the terminal monitor's aesthetic)
# =============================================================================

DARK_BG  = "#1e1e2e"
PANEL_BG = "#2a2a3e"
ACCENT   = "#7aa2f7"
GREEN    = "#9ece6a"
RED      = "#f7768e"
YELLOW   = "#e0af68"
TEXT     = "#cdd6f4"
MUTED    = "#6c7086"


# =============================================================================
#  MAIN APPLICATION
# =============================================================================


class WhitelistManager:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Trusted Port Monitor — Whitelist Manager")
        self.root.geometry("980x600")
        self.root.minsize(720, 460)
        self.root.configure(bg=DARK_BG)

        self._entries: list[str] = []  # current in-memory whitelist
        self._after_id: str | None = None
        self._whitelist_path = Path(WHITELIST_FILE)

        self._build_styles()
        self._build_ui()
        self._load_whitelist()
        self._load_alerts()
        self._schedule_refresh()

    # -------------------------------------------------------------------------
    #  STYLES
    # -------------------------------------------------------------------------

    def _build_styles(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")

        s.configure("TFrame",       background=DARK_BG)
        s.configure("Panel.TFrame", background=PANEL_BG)

        s.configure("TLabel",
                    background=DARK_BG, foreground=TEXT,
                    font=("Consolas", 10))
        s.configure("Header.TLabel",
                    background=DARK_BG, foreground=ACCENT,
                    font=("Consolas", 11, "bold"))
        s.configure("Muted.TLabel",
                    background=PANEL_BG, foreground=MUTED,
                    font=("Consolas", 9))

        s.configure("TButton",
                    background=PANEL_BG, foreground=TEXT,
                    font=("Consolas", 10), borderwidth=1, relief="flat")
        s.map("TButton",
              background=[("active", ACCENT)],
              foreground=[("active", DARK_BG)])

        s.configure("TEntry",
                    fieldbackground=PANEL_BG, foreground=TEXT,
                    font=("Consolas", 10), relief="flat", borderwidth=1)
        s.configure("TScrollbar",
                    background=PANEL_BG, troughcolor=DARK_BG,
                    borderwidth=0, arrowsize=12)

        s.configure("Treeview",
                    background=PANEL_BG, fieldbackground=PANEL_BG,
                    foreground=TEXT, font=("Consolas", 9), rowheight=20)
        s.configure("Treeview.Heading",
                    background=DARK_BG, foreground=ACCENT,
                    font=("Consolas", 9, "bold"))
        s.map("Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", DARK_BG)])

    # -------------------------------------------------------------------------
    #  UI  CONSTRUCTION
    # -------------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root)
        outer.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # ── Header ────────────────────────────────────────────────────────
        ttk.Label(
            outer,
            text="⚙  Trusted Port Monitor — Whitelist Manager",
            style="Header.TLabel",
        ).pack(anchor="w", pady=(0, 8))

        # ── File-path row ─────────────────────────────────────────────────
        file_row = ttk.Frame(outer)
        file_row.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(file_row, text="Whitelist file: ").pack(side=tk.LEFT)
        self._file_var = tk.StringVar(value=str(self._whitelist_path))
        ttk.Entry(file_row, textvariable=self._file_var, width=55).pack(
            side=tk.LEFT, padx=(0, 6), fill=tk.X, expand=True
        )
        ttk.Button(file_row, text="Change…", command=self._browse_whitelist_file).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Button(file_row, text="↺ Reload", command=self._load_whitelist).pack(
            side=tk.LEFT
        )

        # ── Two-panel body ────────────────────────────────────────────────
        body = ttk.Frame(outer)
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(0, weight=1, minsize=320)
        body.columnconfigure(1, weight=1, minsize=320)
        body.rowconfigure(0, weight=1)

        self._build_whitelist_panel(body)
        self._build_alerts_panel(body)

        # ── Status bar ────────────────────────────────────────────────────
        self._status_var = tk.StringVar(value="Ready")
        ttk.Label(
            outer, textvariable=self._status_var, style="TLabel",
            foreground=MUTED, font=("Consolas", 9)
        ).pack(anchor="w", pady=(8, 0))

    def _build_whitelist_panel(self, parent: ttk.Frame) -> None:
        panel = tk.Frame(parent, bg=PANEL_BG)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        tk.Label(
            panel, text="WHITELIST ENTRIES",
            bg=PANEL_BG, fg=ACCENT, font=("Consolas", 11, "bold")
        ).pack(anchor="w", padx=8, pady=(8, 4))

        # Listbox + scrollbar
        lb_frame = tk.Frame(panel, bg=PANEL_BG)
        lb_frame.pack(fill=tk.BOTH, expand=True, padx=8)

        vsb = tk.Scrollbar(lb_frame, orient=tk.VERTICAL, bg=PANEL_BG, troughcolor=DARK_BG)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self._wl_listbox = tk.Listbox(
            lb_frame,
            bg=PANEL_BG, fg=GREEN,
            font=("Consolas", 9),
            selectbackground=ACCENT, selectforeground=DARK_BG,
            relief="flat", bd=0, activestyle="none",
            exportselection=False,
            yscrollcommand=vsb.set,
        )
        vsb.config(command=self._wl_listbox.yview)
        self._wl_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Add-entry controls
        add_row = tk.Frame(panel, bg=PANEL_BG)
        add_row.pack(fill=tk.X, padx=8, pady=(6, 4))

        self._add_var = tk.StringVar()
        add_entry = tk.Entry(
            add_row, textvariable=self._add_var,
            bg=DARK_BG, fg=TEXT, insertbackground=TEXT,
            font=("Consolas", 9), relief="flat", bd=1
        )
        add_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        add_entry.bind("<Return>", lambda _e: self._add_manual())

        ttk.Button(add_row, text="Browse .exe", command=self._browse_exe).pack(
            side=tk.LEFT, padx=(0, 3)
        )
        ttk.Button(add_row, text="+ Add", command=self._add_manual).pack(
            side=tk.LEFT, padx=(0, 3)
        )
        ttk.Button(add_row, text="− Remove", command=self._remove_selected).pack(
            side=tk.LEFT
        )

        # Entry count
        self._wl_count_var = tk.StringVar(value="0 entries")
        tk.Label(
            panel, textvariable=self._wl_count_var,
            bg=PANEL_BG, fg=MUTED, font=("Consolas", 9)
        ).pack(anchor="w", padx=8, pady=(0, 6))

    def _build_alerts_panel(self, parent: ttk.Frame) -> None:
        panel = tk.Frame(parent, bg=PANEL_BG)
        panel.grid(row=0, column=1, sticky="nsew")

        hdr_row = tk.Frame(panel, bg=PANEL_BG)
        hdr_row.pack(fill=tk.X, padx=8, pady=(8, 4))

        tk.Label(
            hdr_row, text="RECENT ALERTS",
            bg=PANEL_BG, fg=YELLOW, font=("Consolas", 11, "bold")
        ).pack(side=tk.LEFT)
        tk.Label(
            hdr_row, text="  double-click to whitelist",
            bg=PANEL_BG, fg=MUTED, font=("Consolas", 9)
        ).pack(side=tk.LEFT)
        ttk.Button(hdr_row, text="↺", width=2, command=self._load_alerts).pack(
            side=tk.RIGHT
        )

        # Treeview
        cols = ("process", "exe_path", "reason", "signed", "status")
        tree_frame = tk.Frame(panel, bg=PANEL_BG)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=8)

        vsb = tk.Scrollbar(tree_frame, orient=tk.VERTICAL, bg=PANEL_BG, troughcolor=DARK_BG)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self._alert_tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings",
            selectmode="browse", yscrollcommand=vsb.set
        )
        vsb.config(command=self._alert_tree.yview)

        self._alert_tree.heading("process",  text="Process")
        self._alert_tree.heading("exe_path", text="Executable Path")
        self._alert_tree.heading("reason",   text="Reason")
        self._alert_tree.heading("signed",   text="Signed")
        self._alert_tree.heading("status",   text="TCP State")

        self._alert_tree.column("process",  width=100, anchor="w")
        self._alert_tree.column("exe_path", width=240, anchor="w")
        self._alert_tree.column("reason",   width=130, anchor="w")
        self._alert_tree.column("signed",   width=70,  anchor="center")
        self._alert_tree.column("status",   width=90,  anchor="center")

        self._alert_tree.tag_configure("warn",   foreground=YELLOW)
        self._alert_tree.tag_configure("danger", foreground=RED)

        self._alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._alert_tree.bind("<Double-1>", self._whitelist_from_alert)

        self._alert_count_var = tk.StringVar(value="No log found")
        tk.Label(
            panel, textvariable=self._alert_count_var,
            bg=PANEL_BG, fg=MUTED, font=("Consolas", 9)
        ).pack(anchor="w", padx=8, pady=(0, 6))

    # -------------------------------------------------------------------------
    #  WHITELIST  I/O
    # -------------------------------------------------------------------------

    def _load_whitelist(self) -> None:
        path = Path(self._file_var.get())
        self._entries = []
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip().lower()
                    if stripped and not stripped.startswith("#"):
                        self._entries.append(stripped)
        self._refresh_listbox()
        self._set_status(f"Loaded {len(self._entries)} entries from {path.name}")

    def _save_whitelist(self) -> None:
        path = Path(self._file_var.get())

        # Preserve any comment / blank lines at the top of the file
        header_lines: list[str] = []
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("#") or not line.strip():
                        header_lines.append(line)
                    else:
                        break  # stop at first data line

        if not header_lines:
            header_lines = [
                "# Pyranoid Signal — Whitelist\n",
                "# One executable path per line (lowercase best case, dont yell at me).\n",
                "# Lines starting with # are comments; blank lines are ignored.\n",
                "# Run whitelist_manager.py then pyranoidsignal.py for easy management of this file with a shitty GUI ;)\n",
                "\n",
            ]

        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(header_lines)
            for entry in sorted(self._entries):
                f.write(entry + "\n")

        self._set_status(f"Saved {len(self._entries)} entries to {path.name}")

    def _refresh_listbox(self) -> None:
        self._wl_listbox.delete(0, tk.END)
        for entry in sorted(self._entries):
            self._wl_listbox.insert(tk.END, entry)
        self._wl_count_var.set(f"{len(self._entries)} entries")

    # -------------------------------------------------------------------------
    #  ADD / REMOVE
    # -------------------------------------------------------------------------

    def _add_entry(self, raw_path: str) -> None:
        """Normalise and add a path; save immediately."""
        normalised = raw_path.strip().lower().replace("/", "\\")
        if not normalised:
            return
        if normalised in self._entries:
            self._set_status(f"Already whitelisted: {normalised}")
            return
        self._entries.append(normalised)
        self._refresh_listbox()
        self._save_whitelist()
        self._set_status(f"Added: {normalised}")

    def _add_manual(self) -> None:
        val = self._add_var.get()
        if val:
            self._add_entry(val)
            self._add_var.set("")

    def _remove_selected(self) -> None:
        sel = self._wl_listbox.curselection()
        if not sel:
            self._set_status("No entry selected.")
            return
        entry = self._wl_listbox.get(sel[0])
        if not messagebox.askyesno(
            "Confirm removal",
            f"Remove this entry from the whitelist?\n\n{entry}",
        ):
            return
        if entry in self._entries:
            self._entries.remove(entry)
        self._refresh_listbox()
        self._save_whitelist()
        self._set_status(f"Removed: {entry}")

    # -------------------------------------------------------------------------
    #  FILE BROWSING
    # -------------------------------------------------------------------------

    def _browse_exe(self) -> None:
        """Open a file-picker to select an .exe and add it directly."""
        path = filedialog.askopenfilename(
            title="Select Executable to Whitelist",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
            initialdir=r"C:\Program Files",
        )
        if path:
            self._add_entry(path)

    def _browse_whitelist_file(self) -> None:
        """Switch to a different whitelist.txt file."""
        path = filedialog.askopenfilename(
            title="Select Whitelist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self._file_var.set(path)
            self._load_whitelist()

    # -------------------------------------------------------------------------
    #  ALERTS PANEL
    # -------------------------------------------------------------------------

    def _load_alerts(self) -> None:
        """Read unique alert rows from the most recent CSV log and populate the tree."""
        self._alert_tree.delete(*self._alert_tree.get_children())

        csvs = sorted(glob.glob(str(LOG_DIR / "*.csv")), reverse=True)
        if not csvs:
            self._alert_count_var.set("No log files found in tpm_logs/")
            return

        latest = csvs[0]
        alerts: list[dict] = []
        try:
            with open(latest, "r", encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    if (
                        row.get("alert", "").lower() == "true"
                        and row.get("whitelisted", "").lower() == "false"
                    ):
                        alerts.append(row)
        except Exception as exc:
            self._alert_count_var.set(f"Error reading log: {exc}")
            return

        # Deduplicate by exe_path, keeping the most-recent occurrence
        seen: set[str] = set()
        unique: list[dict] = []
        for row in reversed(alerts):
            key = row.get("exe_path", "").lower()
            if key not in seen:
                seen.add(key)
                unique.append(row)

        for row in unique[:150]:
            reason = row.get("alert_reason", row.get("alert", ""))
            signed = row.get("signed", "")
            tag    = "danger" if "UNSIGNED" in reason or "LISTENER" in reason else "warn"
            self._alert_tree.insert(
                "", tk.END,
                values=(
                    row.get("process", ""),
                    row.get("exe_path", "").lower(),
                    reason,
                    signed,
                    row.get("status", ""),
                ),
                tags=(tag,),
            )

        log_name = os.path.basename(latest)
        self._alert_count_var.set(
            f"{len(unique)} unique alerts  ·  {log_name}"
        )

    def _whitelist_from_alert(self, _event: tk.Event) -> None:
        """Double-clicking an alert row whitelists that exe immediately."""
        sel = self._alert_tree.selection()
        if not sel:
            return
        values = self._alert_tree.item(sel[0], "values")
        if not values or len(values) < 2:
            return
        exe_path = values[1]
        if exe_path in ("", "unknown", "accessdenied", "processgone", "system"):
            self._set_status("Cannot whitelist placeholder value.")
            return
        self._add_entry(exe_path)

    # -------------------------------------------------------------------------
    #  AUTO-REFRESH + LIFECYCLE
    # -------------------------------------------------------------------------

    def _schedule_refresh(self) -> None:
        """Refresh the alerts panel every 15 seconds."""
        self._load_alerts()
        self._after_id = self.root.after(15_000, self._schedule_refresh)

    def _set_status(self, msg: str) -> None:
        self._status_var.set(msg)

    def on_close(self) -> None:
        if self._after_id:
            self.root.after_cancel(self._after_id)
        self.root.destroy()


# =============================================================================
#  ENTRY POINT
# =============================================================================


def main() -> None:
    root = tk.Tk()
    app = WhitelistManager(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

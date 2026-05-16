"""Small desktop GUI for the Frida Gadget APK patcher."""

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .cli import inspect_apk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None

ROOT_DIR = Path(__file__).resolve().parent.parent
PRESETS = ["", "listen", "script", "dump", "quiet", "debug"]
ARCHES = ["", "arm64", "arm", "x86", "x86_64", "multi-arch"]
BaseTk = TkinterDnD.Tk if TkinterDnD else tk.Tk


class FridaGadgetGui(BaseTk):
    def __init__(self, initial_apk=None):
        super().__init__()
        self.title("Frida Gadget Studio")
        self.geometry("1120x760")
        self.minsize(980, 680)

        self.output_queue = queue.Queue()
        self.worker = None
        self.process = None
        self.status = tk.StringVar(value="Ready")

        self.vars = {
            "apk": tk.StringVar(),
            "arch": tk.StringVar(value="arm64"),
            "preset": tk.StringVar(value="listen"),
            "js": tk.StringVar(),
            "config": tk.StringVar(),
            "local_gadget": tk.StringVar(),
            "output_dir": tk.StringVar(value=str(ROOT_DIR / "output")),
            "main_activity": tk.StringVar(),
            "custom_name": tk.StringVar(),
            "frida_version": tk.StringVar(),
            "dump_package": tk.StringVar(),
            "dump_output": tk.StringVar(value=str(ROOT_DIR / "dumps")),
            "sign": tk.BooleanVar(value=False),
            "backup": tk.BooleanVar(value=True),
            "no_res": tk.BooleanVar(value=False),
            "use_aapt2": tk.BooleanVar(value=False),
            "deep_dump": tk.BooleanVar(value=True),
            "dump_maps": tk.BooleanVar(value=True),
        }

        self._build_style()
        self._build_ui()
        self._enable_drop_support()
        if initial_apk:
            self.load_apk(initial_apk)
        self.after(100, self._drain_output)

    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        self.configure(bg="#0f141b")
        style.configure(".", background="#0f141b", foreground="#e8edf5", fieldbackground="#151c25", borderwidth=0)
        style.configure("TFrame", background="#0f141b")
        style.configure("Shell.TFrame", background="#0f141b")
        style.configure("Sidebar.TFrame", background="#121a24")
        style.configure("Panel.TFrame", background="#151c25")
        style.configure("Card.TFrame", background="#182231")
        style.configure("TLabel", background="#0f141b", foreground="#e8edf5")
        style.configure("Sidebar.TLabel", background="#121a24", foreground="#e8edf5")
        style.configure("Panel.TLabel", background="#151c25", foreground="#e8edf5")
        style.configure("Card.TLabel", background="#182231", foreground="#e8edf5")
        style.configure("Muted.TLabel", background="#151c25", foreground="#92a2b8")
        style.configure("CardMuted.TLabel", background="#182231", foreground="#92a2b8")
        style.configure("Status.TLabel", background="#0b1016", foreground="#a7f3d0", padding=(10, 6))
        style.configure("TButton", background="#263243", foreground="#f8fafc", padding=(11, 7), focusthickness=0)
        style.map("TButton", background=[("active", "#324155"), ("disabled", "#1b2430")], foreground=[("disabled", "#64748b")])
        style.configure("Primary.TButton", background="#2d6cdf", foreground="#ffffff", padding=(14, 8))
        style.map("Primary.TButton", background=[("active", "#2459bc")])
        style.configure("Accent.TButton", background="#20836f", foreground="#ffffff", padding=(12, 8))
        style.map("Accent.TButton", background=[("active", "#176858")])
        style.configure("Danger.TButton", background="#8b3340", foreground="#ffffff", padding=(12, 8))
        style.map("Danger.TButton", background=[("active", "#a13f4b")])
        style.configure("TCheckbutton", background="#182231", foreground="#e8edf5")
        style.map("TCheckbutton", background=[("active", "#182231")])
        style.configure("TEntry", padding=(9, 7), fieldbackground="#101721", foreground="#e8edf5", bordercolor="#263243")
        style.configure("TCombobox", padding=(9, 7), fieldbackground="#101721", foreground="#e8edf5", arrowcolor="#e8edf5")
        style.configure("TNotebook", background="#0f141b", borderwidth=0)
        style.configure("TNotebook.Tab", background="#151c25", foreground="#92a2b8", padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", "#263243")], foreground=[("selected", "#f8fafc")])

    def _build_ui(self):
        outer = ttk.Frame(self, style="Shell.TFrame", padding=16)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer, style="Shell.TFrame")
        header.pack(fill="x", pady=(0, 14))
        title = ttk.Frame(header, style="Shell.TFrame")
        title.pack(side="left", fill="x", expand=True)
        ttk.Label(title, text="Frida Gadget Studio", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        ttk.Label(title, text="Patch, configure, and dump Android apps with fewer sharp edges.", foreground="#94a3b8").pack(anchor="w", pady=(2, 0))
        ttk.Label(header, textvariable=self.status, style="Status.TLabel").pack(side="right", padx=(10, 0))
        ttk.Button(header, text="Doctor", command=self.run_doctor).pack(side="right", padx=(8, 0))
        ttk.Button(header, text="Config", command=self.init_config).pack(side="right")

        main = ttk.Frame(outer)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=0)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(main, style="Sidebar.TFrame", padding=14, width=230)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        sidebar.grid_propagate(False)
        self._build_sidebar(sidebar)

        workspace = ttk.Frame(main, style="Shell.TFrame")
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.rowconfigure(0, weight=1)
        workspace.columnconfigure(0, weight=1)

        tabs = ttk.Notebook(workspace)
        tabs.grid(row=0, column=0, sticky="nsew")

        patch_tab = ttk.Frame(tabs, style="Panel.TFrame", padding=16)
        dump_tab = ttk.Frame(tabs, style="Panel.TFrame", padding=16)
        log_tab = ttk.Frame(tabs, style="Panel.TFrame", padding=16)
        tabs.add(patch_tab, text="Patch")
        tabs.add(dump_tab, text="Dump")
        tabs.add(log_tab, text="Log")

        self._build_patch_panel(patch_tab)
        self._build_dump_panel(dump_tab)
        self._build_log_panel(log_tab)

    def _build_sidebar(self, parent):
        ttk.Label(parent, text="Workflow", style="Sidebar.TLabel", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        ttk.Label(parent, text="Drop an APK or browse. The app fills the boring parts.", style="Sidebar.TLabel", wraplength=190).pack(anchor="w", pady=(4, 16))

        drop = tk.Frame(parent, bg="#0d141d", highlightthickness=1, highlightbackground="#2b3a4f", height=112)
        drop.pack(fill="x", pady=(0, 14))
        drop.pack_propagate(False)
        tk.Label(drop, text="DROP APK", bg="#0d141d", fg="#dbeafe", font=("Segoe UI", 13, "bold")).pack(pady=(24, 2))
        tk.Label(drop, text="or use Browse", bg="#0d141d", fg="#8da2bd", font=("Segoe UI", 9)).pack()
        ttk.Button(parent, text="Browse APK", style="Primary.TButton", command=self.pick_apk).pack(fill="x", pady=(0, 10))
        ttk.Button(parent, text="Open Output", command=lambda: self.open_path(self.vars["output_dir"].get())).pack(fill="x", pady=4)
        ttk.Button(parent, text="Open Dumps", command=lambda: self.open_path(self.vars["dump_output"].get())).pack(fill="x", pady=4)
        ttk.Button(parent, text="Gadget Source", command=self.open_gadget_source).pack(fill="x", pady=4)
        ttk.Button(parent, text="Clear Log", command=lambda: self.log.delete("1.0", "end")).pack(fill="x", pady=(18, 4))

        ttk.Label(parent, text="Selected APK", style="Sidebar.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(18, 4))
        self.apk_summary = ttk.Label(parent, text="None yet", style="Sidebar.TLabel", wraplength=190)
        self.apk_summary.pack(anchor="w")

    def _build_log_panel(self, parent):
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)
        top = ttk.Frame(parent, style="Panel.TFrame")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(top, text="Command Output", style="Panel.TLabel", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Button(top, text="Clear", command=lambda: self.log.delete("1.0", "end")).pack(side="right")

        self.log = tk.Text(
            parent,
            height=14,
            bg="#0b0f14",
            fg="#dbeafe",
            insertbackground="#dbeafe",
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
            padx=12,
            pady=10,
        )
        self.log.grid(row=1, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.log.yview)
        scroll.grid(row=1, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

    def _build_patch_panel(self, parent):
        ttk.Label(parent, text="Patch APK", style="Panel.TLabel", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(parent, text="Drop an APK here or browse. Settings auto-fill from the APK.", style="Muted.TLabel").pack(anchor="w", pady=(2, 12))

        source = ttk.Frame(parent, style="Card.TFrame", padding=12)
        source.pack(fill="x", pady=(0, 10))
        ttk.Label(source, text="Source", style="Card.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        self._path_row(source, "APK", "apk", self.pick_apk)

        profile = ttk.Frame(parent, style="Card.TFrame", padding=12)
        profile.pack(fill="x", pady=(0, 10))
        ttk.Label(profile, text="Profile", style="Card.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        row = ttk.Frame(profile, style="Card.TFrame")
        row.pack(fill="x", pady=5)
        self._combo(row, "Arch", "arch", ARCHES, width=15).pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._combo(row, "Preset", "preset", PRESETS, width=15).pack(side="left", fill="x", expand=True)

        assets = ttk.Frame(parent, style="Card.TFrame", padding=12)
        assets.pack(fill="x", pady=(0, 10))
        ttk.Label(assets, text="Assets", style="Card.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        self._path_row(assets, "Script JS", "js", lambda: self.pick_file("js", [("JavaScript", "*.js"), ("All files", "*.*")]))
        self._path_row(assets, "Config JSON", "config", lambda: self.pick_file("config", [("JSON", "*.json"), ("All files", "*.*")]))
        self._path_row(assets, "Local Gadget", "local_gadget", self.pick_local_gadget)
        self._path_row(assets, "Output Folder", "output_dir", lambda: self.pick_dir("output_dir"))

        details = ttk.Frame(parent, style="Card.TFrame", padding=12)
        details.pack(fill="x", pady=(8, 4))
        ttk.Label(details, text="Advanced", style="Card.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        self._entry(details, "Main Activity", "main_activity").pack(fill="x", pady=4)
        self._entry(details, "Custom Name", "custom_name").pack(fill="x", pady=4)
        self._entry(details, "Frida Version", "frida_version").pack(fill="x", pady=4)

        checks = ttk.Frame(details, style="Card.TFrame")
        checks.pack(fill="x", pady=(8, 12))
        for key, label in [
            ("backup", "Backup"),
            ("sign", "Sign"),
            ("no_res", "No res"),
            ("use_aapt2", "AAPT2"),
        ]:
            ttk.Checkbutton(checks, text=label, variable=self.vars[key]).pack(side="left", padx=(0, 14))

        actions = ttk.Frame(parent, style="Panel.TFrame")
        actions.pack(fill="x", pady=(4, 0))
        self.patch_button = ttk.Button(actions, text="Patch APK", style="Primary.TButton", command=self.patch_apk)
        self.patch_button.pack(side="left")
        self.stop_button = ttk.Button(actions, text="Stop", style="Danger.TButton", command=self.stop_process, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))

    def _build_dump_panel(self, parent):
        ttk.Label(parent, text="Dump DEX", style="Panel.TLabel", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(parent, text="Runs the local frida-dexdump environment.", style="Muted.TLabel").pack(anchor="w", pady=(2, 12))

        target = ttk.Frame(parent, style="Card.TFrame", padding=12)
        target.pack(fill="x", pady=(0, 12))
        ttk.Label(target, text="Target", style="Card.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        self._entry(target, "Package", "dump_package").pack(fill="x", pady=5)
        self._path_row(target, "Dump Folder", "dump_output", lambda: self.pick_dir("dump_output"))
        dump_checks = ttk.Frame(target, style="Card.TFrame")
        dump_checks.pack(fill="x", pady=(8, 12))
        ttk.Checkbutton(dump_checks, text="Deep search", variable=self.vars["deep_dump"]).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(dump_checks, text="Maps", variable=self.vars["dump_maps"]).pack(side="left")

        ttk.Button(parent, text="Run Dumper", style="Primary.TButton", command=self.run_dump).pack(anchor="w")

        ttk.Separator(parent).pack(fill="x", pady=18)
        ttk.Label(parent, text="Quick Commands", style="Panel.TLabel", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Button(parent, text="Open Output", command=lambda: self.open_path(self.vars["output_dir"].get())).pack(fill="x", pady=(10, 4))
        ttk.Button(parent, text="Open Dumps", command=lambda: self.open_path(self.vars["dump_output"].get())).pack(fill="x", pady=4)
        ttk.Button(parent, text="Open Gadget Source", command=self.open_gadget_source).pack(fill="x", pady=4)
        ttk.Button(parent, text="Clear Log", command=lambda: self.log.delete("1.0", "end")).pack(fill="x", pady=4)

    def _entry(self, parent, label, key):
        frame = ttk.Frame(parent, style="Card.TFrame")
        ttk.Label(frame, text=label, style="Card.TLabel", width=14).pack(side="left")
        ttk.Entry(frame, textvariable=self.vars[key]).pack(side="left", fill="x", expand=True)
        return frame

    def _combo(self, parent, label, key, values, width=12):
        frame = ttk.Frame(parent, style="Card.TFrame")
        ttk.Label(frame, text=label, style="Card.TLabel").pack(anchor="w")
        ttk.Combobox(frame, textvariable=self.vars[key], values=values, state="readonly", width=width).pack(fill="x")
        return frame

    def _path_row(self, parent, label, key, command):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill="x", pady=5)
        ttk.Label(frame, text=label, style="Card.TLabel", width=14).pack(side="left")
        ttk.Entry(frame, textvariable=self.vars[key]).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(frame, text="Browse", command=command).pack(side="left")

    def pick_apk(self):
        path = filedialog.askopenfilename(title="Choose APK", filetypes=[("Android APK", "*.apk"), ("All files", "*.*")])
        if path:
            self.load_apk(path)

    def load_apk(self, path):
        apk = str(Path(path).expanduser())
        if not apk.lower().endswith(".apk"):
            self._write_log(f"\n[skip] Not an APK: {apk}\n")
            self.status.set("Not an APK")
            return
        self.vars["apk"].set(apk)
        self.vars["output_dir"].set(str(Path(apk).parent / "output"))
        self.status.set("Inspecting APK")
        self._write_log(f"\n[auto] Inspecting APK: {apk}\n")
        try:
            info = inspect_apk(apk)
        except Exception as exc:
            self._write_log(f"[auto] APK inspect failed: {exc}\n")
            self.status.set("Inspect failed")
            return

        self.vars["arch"].set(info.get("recommended_arch") or "arm64")
        self.vars["preset"].set(info.get("recommended_preset") or "listen")
        self.vars["main_activity"].set(info.get("main_activity") or "")
        self.vars["dump_package"].set(info.get("package") or "")
        self.vars["dump_output"].set(info.get("dump_output") or str(Path(apk).parent / "dumps"))
        self.apk_summary.configure(
            text="{name}\n{package}\n{arch}".format(
                name=Path(apk).name,
                package=info.get("package") or "package unknown",
                arch=info.get("recommended_arch") or "arm64",
            )
        )

        architectures = ", ".join(info.get("architectures") or ["none found"])
        self._write_log(
            "[auto] package={package}\n"
            "[auto] main={main}\n"
            "[auto] arch={arch} ({architectures})\n"
            "[auto] output={output}\n".format(
                package=info.get("package") or "unknown",
                main=info.get("main_activity") or "unknown",
                arch=info.get("recommended_arch") or "arm64",
                architectures=architectures,
                output=self.vars["output_dir"].get(),
            )
        )
        for warning in info.get("warnings") or []:
            self._write_log(f"[warn] {warning}\n")
        self.status.set("APK ready")

    def pick_local_gadget(self):
        path = filedialog.askopenfilename(
            title="Choose libfrida-gadget.so",
            filetypes=[("Shared library", "*.so"), ("All files", "*.*")],
        )
        if path:
            self.vars["local_gadget"].set(path)

    def pick_file(self, key, filetypes):
        path = filedialog.askopenfilename(title=f"Choose {key}", filetypes=filetypes)
        if path:
            self.vars[key].set(path)

    def pick_dir(self, key):
        path = filedialog.askdirectory(title=f"Choose {key}")
        if path:
            self.vars[key].set(path)

    def patch_apk(self):
        apk = self.vars["apk"].get().strip()
        if not apk:
            messagebox.showerror("Missing APK", "Choose an APK first.")
            return

        cmd = [sys.executable, "-m", "scripts.cli"]
        self._add_option(cmd, "--arch", self.vars["arch"].get())
        self._add_option(cmd, "--preset", self.vars["preset"].get())
        self._add_option(cmd, "--js", self.vars["js"].get())
        self._add_option(cmd, "--config", self.vars["config"].get())
        self._add_option(cmd, "--local-gadget", self.vars["local_gadget"].get())
        self._add_option(cmd, "--output-dir", self.vars["output_dir"].get())
        self._add_option(cmd, "--main-activity", self.vars["main_activity"].get())
        self._add_option(cmd, "--custom-gadget-name", self.vars["custom_name"].get())
        self._add_option(cmd, "--frida-version", self.vars["frida_version"].get())
        self._add_flag(cmd, "--backup", self.vars["backup"].get())
        self._add_flag(cmd, "--sign", self.vars["sign"].get())
        self._add_flag(cmd, "--no-res", self.vars["no_res"].get())
        self._add_flag(cmd, "--use-aapt2", self.vars["use_aapt2"].get())
        cmd.append(apk)
        self.run_command(cmd)

    def run_doctor(self):
        self.run_command([sys.executable, "-m", "scripts.cli", "--doctor"])

    def init_config(self):
        preset = self.vars["preset"].get().strip() or "listen"
        self.run_command([sys.executable, "-m", "scripts.cli", "--init-config", preset])

    def run_dump(self):
        package = self.vars["dump_package"].get().strip()
        if not package:
            messagebox.showerror("Missing Package", "Enter an Android package name.")
            return

        cmd = [sys.executable, "-m", "scripts.cli", "--dump", package]
        self._add_option(cmd, "--dump-output", self.vars["dump_output"].get())
        self._add_flag(cmd, "--deep-dump", self.vars["deep_dump"].get())
        self._add_flag(cmd, "--dump-maps", self.vars["dump_maps"].get())
        self.run_command(cmd)

    def run_command(self, cmd):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Busy", "A command is already running.")
            return

        self._set_busy(True)
        self.status.set("Running")
        self._write_log("\n> " + subprocess.list2cmdline(cmd) + "\n")
        self.worker = threading.Thread(target=self._run_command_worker, args=(cmd,), daemon=True)
        self.worker.start()

    def _run_command_worker(self, cmd):
        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(ROOT_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            for line in self.process.stdout:
                self.output_queue.put(line)
            code = self.process.wait()
            self.output_queue.put(f"\n[exit {code}]\n")
            self.output_queue.put(("__STATUS__", "Done" if code == 0 else f"Exit {code}"))
        except Exception as exc:
            self.output_queue.put(f"\n[error] {exc}\n")
            self.output_queue.put(("__STATUS__", "Error"))
        finally:
            self.process = None
            self.output_queue.put("__DONE__")

    def stop_process(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self._write_log("\n[stop requested]\n")

    def _drain_output(self):
        try:
            while True:
                item = self.output_queue.get_nowait()
                if item == "__DONE__":
                    self._set_busy(False)
                elif isinstance(item, tuple) and item[0] == "__STATUS__":
                    self.status.set(item[1])
                else:
                    self._write_log(item)
        except queue.Empty:
            pass
        self.after(100, self._drain_output)

    def _write_log(self, text):
        self.log.insert("end", text)
        self.log.see("end")

    def _set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.patch_button.configure(state=state)
        self.stop_button.configure(state="normal" if busy else "disabled")
        if not busy and self.status.get() == "Running":
            self.status.set("Ready")

    def _add_option(self, cmd, option, value):
        value = value.strip() if isinstance(value, str) else value
        if value:
            cmd.extend([option, value])

    def _add_flag(self, cmd, option, enabled):
        if enabled:
            cmd.append(option)

    def open_path(self, path):
        path = path.strip()
        if not path:
            return
        Path(path).mkdir(parents=True, exist_ok=True)
        os.startfile(path)

    def open_gadget_source(self):
        gadget = ROOT_DIR.parent / "frida-source" / "subprojects" / "frida-core" / "lib" / "gadget" / "gadget.vala"
        if gadget.exists():
            os.startfile(gadget)
        else:
            messagebox.showerror("Missing File", f"Cannot find:\n{gadget}")

    def _enable_drop_support(self):
        if DND_FILES is None:
            self._write_log("[info] Drag-and-drop package is not installed. Drag APK onto the .bat launcher or use Browse.\n")
            return
        self.drop_target_register(DND_FILES)
        self.dnd_bind("<<Drop>>", self._on_drop)
        self._write_log("[info] Drag-and-drop enabled. Drop an APK anywhere on this window.\n")

    def _on_drop(self, event):
        paths = self.tk.splitlist(event.data)
        for path in paths:
            if str(path).lower().endswith(".apk"):
                self.load_apk(path)
                return
        self._write_log(f"\n[drop] No APK found in: {event.data}\n")


def main():
    initial_apk = sys.argv[1] if len(sys.argv) > 1 else None
    app = FridaGadgetGui(initial_apk=initial_apk)
    app.mainloop()


if __name__ == "__main__":
    main()

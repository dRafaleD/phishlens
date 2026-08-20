from __future__ import annotations

import tkinter as tk
import sys
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from tkinter import filedialog, messagebox, ttk
from typing import Callable

if __package__ in {None, ""}:
    package_root = Path(__file__).resolve().parent.parent
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))
    from phishlens.analyzer import AnalysisResult, Finding, analyze_eml
    from phishlens.classifier import ModelError, NaiveBayesModel, TrainingReport, train_from_directory
    from phishlens.reporting import render_batch_csv, render_batch_text, render_text, render_training_report
else:
    from .analyzer import AnalysisResult, Finding, analyze_eml
    from .classifier import ModelError, NaiveBayesModel, TrainingReport, train_from_directory
    from .reporting import render_batch_csv, render_batch_text, render_text, render_training_report


class GuiError(RuntimeError):
    """Raised when the desktop UI cannot start."""


@dataclass
class _ModelState:
    path: Path | None = None
    model: NaiveBayesModel | None = None


class PhishLensApp:
    CANVAS = "#060B09"
    SURFACE = "#0D1613"
    SURFACE_ALT = "#111E1A"
    INK = "#D9FCE8"
    MUTED = "#789889"
    BRAND = "#09120F"
    ACCENT = "#35F28C"
    ACCENT_ACTIVE = "#6AFFAD"
    BORDER = "#203A31"
    SAFE = "#35F28C"
    WARNING = "#F0B84B"
    DANGER = "#FF6B62"

    def __init__(self, root: tk.Tk, initial_model_path: Path | None = None) -> None:
        self.root = root
        self.root.title("PhishLens // Email Risk Triage")
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = min(1080, max(760, screen_width - 80))
        window_height = min(760, max(600, screen_height - 120))
        window_x = max(0, (screen_width - window_width) // 2)
        window_y = max(0, (screen_height - window_height) // 2)
        self.root.geometry(f"{window_width}x{window_height}+{window_x}+{window_y}")
        self.root.minsize(min(920, window_width), min(680, window_height))
        self.root.configure(background=self.CANVAS)

        self.status_var = tk.StringVar(value="Ready")
        self.model_label_var = tk.StringVar(value="No model loaded")
        self.analysis_file_var = tk.StringVar()
        self.scan_directory_var = tk.StringVar()
        self.scan_recursive = tk.BooleanVar(value=True)
        self.train_dataset_var = tk.StringVar()
        self.train_output_var = tk.StringVar(value="phishlens-model.json")
        self.validation_split_var = tk.StringVar(value="0.2")
        self.score_var = tk.StringVar(value="--")
        self.verdict_var = tk.StringVar(value="NO RESULT")
        self.signal_var = tk.StringVar(value="0")
        self.model_score_var = tk.StringVar(value="Not loaded")
        self.evidence_var = tk.StringVar(value="Select a result row to inspect its evidence.")

        self.model_state = _ModelState()
        self._busy = False
        self._action_buttons: list[ttk.Button] = []
        self._row_payload: dict[str, Finding | AnalysisResult] = {}
        self._displayed_report = ""
        self._scan_results: list[AnalysisResult] = []

        self._configure_styles()
        self._build_layout()
        self._show_welcome()
        if initial_model_path is not None:
            self._load_model(initial_model_path, announce=False)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("App.TFrame", background=self.CANVAS)
        style.configure("Surface.TFrame", background=self.SURFACE)
        style.configure(
            "TNotebook",
            background=self.CANVAS,
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        style.configure(
            "TNotebook.Tab",
            background="#0A110F",
            foreground=self.MUTED,
            font=("Cascadia Mono", 9, "bold"),
            padding=(18, 9),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.SURFACE), ("active", self.SURFACE_ALT)],
            foreground=[("selected", self.ACCENT), ("active", self.INK)],
        )
        style.configure(
            "TButton",
            font=("Cascadia Mono", 9),
            padding=(12, 7),
            borderwidth=1,
            background=self.SURFACE_ALT,
            foreground=self.INK,
            bordercolor=self.BORDER,
            lightcolor=self.BORDER,
            darkcolor=self.BORDER,
        )
        style.map(
            "TButton",
            background=[("active", "#193128"), ("disabled", "#101815")],
            foreground=[("disabled", "#4F675C")],
        )
        style.configure(
            "Primary.TButton",
            font=("Cascadia Mono", 9, "bold"),
            background=self.ACCENT,
            foreground="#04100A",
            borderwidth=0,
            padding=(18, 9),
        )
        style.map(
            "Primary.TButton",
            background=[("active", self.ACCENT_ACTIVE), ("disabled", "#254B38")],
            foreground=[("disabled", "#668575")],
        )
        style.configure(
            "TEntry",
            padding=8,
            fieldbackground="#07100D",
            foreground=self.INK,
            insertcolor=self.ACCENT,
            bordercolor=self.BORDER,
            lightcolor=self.BORDER,
            darkcolor=self.BORDER,
        )
        style.configure("TCheckbutton", background=self.SURFACE, foreground=self.INK, font=("Cascadia Mono", 9))
        style.map("TCheckbutton", background=[("active", self.SURFACE)], foreground=[("active", self.ACCENT)])
        style.configure(
            "Treeview",
            background="#08110E",
            fieldbackground="#08110E",
            foreground=self.INK,
            borderwidth=0,
            rowheight=30,
            font=("Cascadia Mono", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#13231D",
            foreground=self.ACCENT,
            relief="flat",
            font=("Cascadia Mono", 9, "bold"),
            padding=(8, 8),
        )
        style.map("Treeview", background=[("selected", "#193D2E")], foreground=[("selected", "#FFFFFF")])
        style.configure("Horizontal.TProgressbar", troughcolor="#14231D", background=self.ACCENT, borderwidth=0)
        style.configure(
            "TScrollbar",
            background="#193128",
            troughcolor="#08110E",
            arrowcolor=self.MUTED,
            bordercolor=self.BORDER,
        )

    def _build_layout(self) -> None:
        container = ttk.Frame(self.root, style="App.TFrame", padding=(18, 14, 18, 10))
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(3, weight=1)

        self._build_header(container).grid(row=0, column=0, sticky="ew")
        self._build_model_bar(container).grid(row=1, column=0, sticky="ew", pady=(8, 8))

        self.notebook = ttk.Notebook(container)
        self.notebook.grid(row=2, column=0, sticky="ew")
        self.notebook.add(self._build_analyze_tab(self.notebook), text="  Analyze email  ")
        self.notebook.add(self._build_scan_tab(self.notebook), text="  Scan folder  ")
        self.notebook.add(self._build_train_tab(self.notebook), text="  Train model  ")

        self._build_results(container).grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        self._build_status_bar(container).grid(row=4, column=0, sticky="ew", pady=(7, 0))

    def _build_header(self, parent: ttk.Frame) -> tk.Frame:
        header = tk.Frame(
            parent,
            background=self.BRAND,
            padx=20,
            pady=10,
            highlightthickness=1,
            highlightbackground=self.BORDER,
        )
        header.columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="root@phishlens:~$ inspect --safe",
            background=self.BRAND,
            foreground="#B7D8CE",
            font=("Cascadia Mono", 9),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            header,
            text="PHISHLENS // MAIL TRIAGE",
            background=self.BRAND,
            foreground="#FFFFFF",
            font=("Cascadia Mono", 18, "bold"),
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        badge = tk.Label(
            header,
            text="[ LOCAL / OFFLINE ]",
            background="#10251C",
            foreground=self.ACCENT,
            font=("Cascadia Mono", 9, "bold"),
            padx=12,
            pady=7,
        )
        badge.grid(row=0, column=1, rowspan=2, sticky="e")
        return header

    def _build_model_bar(self, parent: ttk.Frame) -> ttk.Frame:
        bar = ttk.Frame(parent, style="Surface.TFrame", padding=(12, 7))
        bar.columnconfigure(1, weight=1)
        tk.Label(
            bar,
            text="MODEL",
            background=self.SURFACE,
            foreground=self.MUTED,
            font=("Cascadia Mono", 8, "bold"),
        ).grid(row=0, column=0, padx=(0, 12))
        self.model_status_label = tk.Label(
            bar,
            textvariable=self.model_label_var,
            background=self.SURFACE,
            foreground=self.MUTED,
            font=("Cascadia Mono", 9),
            anchor="w",
        )
        self.model_status_label.grid(row=0, column=1, sticky="ew")
        button = ttk.Button(bar, text="Load model", command=self._choose_model)
        button.grid(row=0, column=2)
        self._action_buttons.append(button)
        return bar

    def _tab_shell(self, parent: ttk.Notebook, title: str, help_text: str) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Surface.TFrame", padding=(16, 12))
        frame.columnconfigure(0, minsize=100)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(2, minsize=96)
        frame.columnconfigure(3, minsize=148)
        tk.Label(
            frame,
            text=f"{title.upper()}  //  {help_text}",
            background=self.SURFACE,
            foreground=self.MUTED,
            font=("Cascadia Mono", 8),
        ).grid(row=0, column=0, columnspan=4, sticky="w")
        return frame

    def _build_analyze_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = self._tab_shell(
            parent,
            "Inspect one message",
            "Export the message as an .eml file. PhishLens will not open links or attachments.",
        )
        tk.Label(
            frame,
            text="EML file",
            background=self.SURFACE,
            foreground=self.INK,
            font=("Cascadia Mono", 9, "bold"),
        ).grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(frame, textvariable=self.analysis_file_var).grid(row=1, column=1, sticky="ew", padx=(12, 8), pady=(10, 0))
        ttk.Button(frame, text="Browse...", command=self._choose_analysis_file).grid(row=1, column=2, sticky="ew", pady=(10, 0))
        button = ttk.Button(frame, text="Analyze message", style="Primary.TButton", command=self._analyze_selected_file)
        button.grid(row=1, column=3, padx=(8, 0), pady=(10, 0), sticky="ew")
        self._action_buttons.append(button)
        return frame

    def _build_scan_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = self._tab_shell(
            parent,
            "Review a mail collection",
            "Scan every .eml file in a folder and rank the riskiest messages first.",
        )
        tk.Label(
            frame,
            text="Folder",
            background=self.SURFACE,
            foreground=self.INK,
            font=("Cascadia Mono", 9, "bold"),
        ).grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(frame, textvariable=self.scan_directory_var).grid(row=1, column=1, sticky="ew", padx=(12, 8), pady=(10, 0))
        ttk.Button(frame, text="Browse...", command=self._choose_scan_directory).grid(row=1, column=2, sticky="ew", pady=(10, 0))
        ttk.Checkbutton(frame, text="Include subfolders", variable=self.scan_recursive).grid(
            row=2, column=1, sticky="w", padx=(12, 0), pady=(8, 0)
        )
        button = ttk.Button(frame, text="Scan folder", style="Primary.TButton", command=self._scan_directory)
        button.grid(row=1, column=3, padx=(8, 0), pady=(10, 0), sticky="ew")
        self._action_buttons.append(button)
        ttk.Button(frame, text="Export CSV...", command=self._export_scan_csv).grid(
            row=2, column=3, padx=(8, 0), pady=(8, 0), sticky="ew"
        )
        return frame

    def _build_train_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = self._tab_shell(
            parent,
            "Teach a local model",
            "Choose a dataset containing phishing/ and legitimate/ folders. Email content stays on this device.",
        )
        labels = ("Dataset", "Save model")
        for row, label in enumerate(labels, start=1):
            tk.Label(
                frame,
                text=label,
                background=self.SURFACE,
                foreground=self.INK,
                font=("Cascadia Mono", 9, "bold"),
            ).grid(row=row, column=0, sticky="w", pady=((10 if row == 1 else 8), 0))

        ttk.Entry(frame, textvariable=self.train_dataset_var).grid(row=1, column=1, sticky="ew", padx=(12, 8), pady=(10, 0))
        ttk.Button(frame, text="Browse...", command=self._choose_train_dataset).grid(row=1, column=2, sticky="ew", pady=(10, 0))
        ttk.Entry(frame, textvariable=self.train_output_var).grid(row=2, column=1, sticky="ew", padx=(12, 8), pady=(8, 0))
        ttk.Button(frame, text="Save as...", command=self._choose_train_output).grid(row=2, column=2, sticky="ew", pady=(8, 0))
        validation_row = ttk.Frame(frame, style="Surface.TFrame")
        validation_row.grid(row=1, column=3, sticky="ew", padx=(8, 0), pady=(10, 0))
        tk.Label(
            validation_row,
            text="VAL SPLIT",
            background=self.SURFACE,
            foreground=self.MUTED,
            font=("Cascadia Mono", 8, "bold"),
        ).grid(row=0, column=0, padx=(0, 6))
        ttk.Entry(validation_row, textvariable=self.validation_split_var, width=5).grid(row=0, column=1)
        button = ttk.Button(frame, text="Train model", style="Primary.TButton", command=self._train_model)
        button.grid(row=2, column=3, padx=(8, 0), pady=(8, 0), sticky="ew")
        self._action_buttons.append(button)
        return frame

    def _build_results(self, parent: ttk.Frame) -> ttk.Frame:
        panel = ttk.Frame(parent, style="App.TFrame")
        for column in range(4):
            panel.columnconfigure(column, weight=1, uniform="metric")
        panel.rowconfigure(1, weight=1)

        self.verdict_value_label = self._metric_card(panel, 0, "RISK", self.verdict_var, self.MUTED)
        self.score_value_label = self._metric_card(panel, 1, "SCORE", self.score_var, self.INK)
        self._metric_card(panel, 2, "SIGNALS", self.signal_var, self.INK)
        self._metric_card(panel, 3, "LOCAL MODEL", self.model_score_var, self.INK)

        results_body = ttk.Frame(panel, style="App.TFrame")
        results_body.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(8, 0))
        for column in range(2):
            results_body.columnconfigure(column, weight=1, uniform="result-pane")
        results_body.rowconfigure(0, weight=1)

        findings_panel = ttk.Frame(results_body, style="Surface.TFrame", padding=10)
        findings_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        findings_panel.columnconfigure(0, weight=1)
        findings_panel.rowconfigure(1, weight=1)
        tk.Label(
            findings_panel,
            text="SIGNAL REVIEW",
            background=self.SURFACE,
            foreground=self.MUTED,
            font=("Cascadia Mono", 9, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.results_tree = ttk.Treeview(
            findings_panel,
            columns=("kind", "score", "detail", "source"),
            show="headings",
            selectmode="browse",
            height=5,
        )
        self.results_tree.grid(row=1, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(findings_panel, orient="vertical", command=self.results_tree.yview)
        tree_scroll.grid(row=1, column=1, sticky="ns")
        self.results_tree.configure(yscrollcommand=tree_scroll.set)
        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_selected)
        self.results_tree.tag_configure("high", foreground=self.DANGER)
        self.results_tree.tag_configure("medium", foreground=self.WARNING)
        self.results_tree.tag_configure("low", foreground=self.MUTED)
        self.results_tree.tag_configure("safe", foreground=self.SAFE)
        self.results_tree.tag_configure("welcome", foreground=self.MUTED)

        self.evidence_label = tk.Label(
            findings_panel,
            textvariable=self.evidence_var,
            background=self.SURFACE_ALT,
            foreground=self.MUTED,
            font=("Cascadia Mono", 8),
            anchor="w",
            justify="left",
            wraplength=410,
            padx=10,
            pady=8,
        )
        self.evidence_label.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        findings_panel.bind(
            "<Configure>",
            lambda event: self.evidence_label.configure(wraplength=max(260, event.width - 34)),
        )

        report_panel = ttk.Frame(results_body, style="Surface.TFrame", padding=10)
        report_panel.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        report_panel.columnconfigure(0, weight=1)
        report_panel.rowconfigure(1, weight=1)
        report_header = ttk.Frame(report_panel, style="Surface.TFrame")
        report_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        report_header.columnconfigure(0, weight=1)
        tk.Label(
            report_header,
            text="FULL REPORT",
            background=self.SURFACE,
            foreground=self.MUTED,
            font=("Cascadia Mono", 9, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(report_header, text="Copy", command=self._copy_report).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(report_header, text="Save...", command=self._save_report).grid(row=0, column=2)

        self.output = tk.Text(
            report_panel,
            wrap="word",
            width=42,
            height=5,
            borderwidth=0,
            background="#07100D",
            foreground=self.INK,
            insertbackground=self.ACCENT,
            selectbackground="#1D553C",
            font=("Cascadia Mono", 9),
            padx=12,
            pady=10,
        )
        self.output.grid(row=1, column=0, sticky="nsew")
        report_scroll = ttk.Scrollbar(report_panel, orient="vertical", command=self.output.yview)
        report_scroll.grid(row=1, column=1, sticky="ns")
        self.output.configure(yscrollcommand=report_scroll.set, state="disabled")

        return panel

    def _metric_card(
        self,
        parent: ttk.Frame,
        column: int,
        title: str,
        variable: tk.StringVar,
        color: str,
    ) -> tk.Label:
        card = tk.Frame(
            parent,
            background=self.SURFACE,
            padx=12,
            pady=8,
            highlightthickness=1,
            highlightbackground=self.BORDER,
        )
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 4, 0 if column == 3 else 4))
        card.columnconfigure(0, weight=1)
        tk.Label(
            card,
            text=title,
            background=self.SURFACE,
            foreground=self.MUTED,
            font=("Cascadia Mono", 8, "bold"),
        ).grid(row=0, column=0, sticky="w")
        value_label = tk.Label(
            card,
            textvariable=variable,
            background=self.SURFACE,
            foreground=color,
            font=("Cascadia Mono", 13, "bold"),
            anchor="w",
        )
        value_label.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        return value_label

    def _build_status_bar(self, parent: ttk.Frame) -> ttk.Frame:
        bar = ttk.Frame(parent, style="App.TFrame")
        bar.columnconfigure(0, weight=1)
        tk.Label(
            bar,
            textvariable=self.status_var,
            background=self.CANVAS,
            foreground=self.MUTED,
            font=("Cascadia Mono", 8),
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.grid(row=0, column=1, sticky="e")
        self.progress.grid_remove()
        return bar

    def _show_welcome(self) -> None:
        self._configure_tree("Step", "", "What to do", "")
        self._clear_tree()
        self.results_tree.insert("", "end", values=("1", "", "Choose an exported .eml file", ""), tags=("welcome",))
        self.results_tree.insert("", "end", values=("2", "", "Analyze it without opening links", ""), tags=("welcome",))
        self.results_tree.insert("", "end", values=("3", "", "Review each explainable signal", ""), tags=("welcome",))
        self._set_output(
            "PhishLens is ready.\n\n"
            "Start in Analyze email for one message, or use Scan folder to rank a collection. "
            "Loading a trained model is optional; transparent security rules always run.\n\n"
            "Safety note: PhishLens never visits links and never executes attachments."
        )

    def _configure_tree(self, kind: str, score: str, detail: str, source: str) -> None:
        headings = (kind, score, detail, source)
        widths = (74, 54, 220, 110)
        anchors = ("center", "center", "w", "w")
        for column, heading, width, anchor in zip(self.results_tree["columns"], headings, widths, anchors):
            self.results_tree.heading(column, text=heading)
            self.results_tree.column(column, width=width, minwidth=40, anchor=anchor, stretch=column in {"detail", "source"})

    def _clear_tree(self) -> None:
        self._row_payload.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

    def _set_output(self, content: str) -> None:
        self._displayed_report = content
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", content)
        self.output.see("1.0")
        self.output.configure(state="disabled")

    def _set_status(self, message: str) -> None:
        self.status_var.set(message)

    def _set_busy(self, busy: bool, message: str) -> None:
        self._busy = busy
        self._set_status(message)
        for button in self._action_buttons:
            button.configure(state="disabled" if busy else "normal")
        if busy:
            self.progress.grid()
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.grid_remove()

    def _run_task(
        self,
        message: str,
        task: Callable[[], object],
        on_success: Callable[[object], None],
    ) -> None:
        if self._busy:
            return
        self._set_busy(True, message)

        def worker() -> None:
            try:
                payload = task()
                error: Exception | None = None
            except Exception as caught_error:  # The UI reports operational errors without crashing.
                payload = None
                error = caught_error
            self.root.after(0, lambda: self._finish_task(payload, error, on_success))

        Thread(target=worker, daemon=True).start()

    def _finish_task(
        self,
        payload: object,
        error: Exception | None,
        on_success: Callable[[object], None],
    ) -> None:
        self._set_busy(False, "Ready")
        if error is not None:
            messagebox.showerror("PhishLens", str(error))
            self._set_status("Operation failed")
            return
        on_success(payload)

    def _choose_model(self) -> None:
        if self._busy:
            return
        selection = filedialog.askopenfilename(
            title="Select a trained model",
            filetypes=[("JSON model", "*.json"), ("All files", "*.*")],
        )
        if selection:
            self._load_model(Path(selection))

    def _load_model(self, path: Path, announce: bool = True) -> None:
        try:
            model = NaiveBayesModel.load(path)
        except (OSError, ModelError, ValueError) as error:
            messagebox.showerror("PhishLens", str(error))
            self._set_status("Model could not be loaded")
            return
        self.model_state = _ModelState(path=path, model=model)
        self.model_label_var.set(path.name)
        self.model_status_label.configure(foreground=self.SAFE)
        self.model_score_var.set("Ready")
        self._set_status(f"Loaded model: {path.name}")
        if announce:
            messagebox.showinfo("PhishLens", f"Model loaded:\n{path}")

    def _choose_analysis_file(self) -> None:
        selection = filedialog.askopenfilename(
            title="Choose an exported email",
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")],
        )
        if selection:
            self.analysis_file_var.set(selection)

    def _choose_scan_directory(self) -> None:
        selection = filedialog.askdirectory(title="Choose a folder containing .eml files")
        if selection:
            self.scan_directory_var.set(selection)

    def _choose_train_dataset(self) -> None:
        selection = filedialog.askdirectory(title="Choose a training dataset folder")
        if selection:
            self.train_dataset_var.set(selection)
            suggested = Path(selection) / "phishlens-model.json"
            if self.train_output_var.get() == "phishlens-model.json":
                self.train_output_var.set(str(suggested))

    def _choose_train_output(self) -> None:
        selection = filedialog.asksaveasfilename(
            title="Choose where to save the model",
            defaultextension=".json",
            initialfile=Path(self.train_output_var.get() or "phishlens-model.json").name,
            filetypes=[("JSON model", "*.json"), ("All files", "*.*")],
        )
        if selection:
            self.train_output_var.set(selection)

    def _analyze_selected_file(self) -> None:
        path = Path(self.analysis_file_var.get().strip())
        if not path.is_file() or path.suffix.lower() != ".eml":
            messagebox.showerror("PhishLens", "Choose a valid .eml file first.")
            return
        model = self.model_state.model
        self._run_task(
            f"Analyzing {path.name}...",
            lambda: analyze_eml(path, model=model),
            lambda payload: self._show_analysis(payload),
        )

    def _show_analysis(self, payload: object) -> None:
        if not isinstance(payload, AnalysisResult):
            raise GuiError("analysis returned an unexpected result")
        result = payload
        self._update_metrics(result.score, result.verdict, len(result.findings), result)
        self._configure_tree("Severity", "Points", "Finding", "Rule")
        self._clear_tree()
        if not result.findings:
            self.results_tree.insert("", "end", values=("SAFE", "0", "No heuristic warning triggered", "-"), tags=("safe",))
        for finding in result.findings:
            item = self.results_tree.insert(
                "",
                "end",
                values=(finding.severity.upper(), f"+{finding.points}", finding.title, finding.rule_id),
                tags=(finding.severity,),
            )
            self._row_payload[item] = finding
        self.evidence_var.set("Select a finding to inspect the evidence behind it.")
        self._set_output(render_text(result))
        self._set_status(f"Analyzed {Path(result.source).name}: {result.verdict}, {result.score}/100")

    def _scan_directory(self) -> None:
        root = Path(self.scan_directory_var.get().strip())
        if not root.is_dir():
            messagebox.showerror("PhishLens", "Choose a valid folder first.")
            return
        recursive = self.scan_recursive.get()
        model = self.model_state.model

        def scan() -> tuple[Path, list[AnalysisResult], int]:
            iterator = root.rglob("*.eml") if recursive else root.glob("*.eml")
            files = sorted((item for item in iterator if item.is_file()), key=lambda item: str(item).casefold())
            if not files:
                raise GuiError("No .eml files were found in that folder.")
            results: list[AnalysisResult] = []
            skipped = 0
            for file_path in files:
                try:
                    results.append(analyze_eml(file_path, model=model))
                except (OSError, ValueError):
                    skipped += 1
            if not results:
                raise GuiError("Messages were found, but none could be analyzed.")
            return root, results, skipped

        self._run_task(f"Scanning {root.name}...", scan, self._show_scan_results)

    def _show_scan_results(self, payload: object) -> None:
        if not isinstance(payload, tuple) or len(payload) != 3:
            raise GuiError("folder scan returned an unexpected result")
        root, results, skipped = payload
        if not isinstance(root, Path) or not isinstance(results, list) or not isinstance(skipped, int):
            raise GuiError("folder scan returned invalid data")
        ordered = sorted(results, key=lambda item: (-item.score, item.source.casefold()))
        self._scan_results = ordered
        highest = ordered[0]
        signal_count = sum(len(result.findings) for result in results)
        self._update_metrics(highest.score, highest.verdict, signal_count, highest)
        self._configure_tree("Risk", "Score", "Subject", "File")
        self._clear_tree()
        for result in ordered:
            tag = "high" if result.verdict == "high-risk" else "medium" if result.verdict == "suspicious" else "safe"
            item = self.results_tree.insert(
                "",
                "end",
                values=(result.verdict.upper(), result.score, result.headers["subject"] or "<missing>", Path(result.source).name),
                tags=(tag,),
            )
            self._row_payload[item] = result
        report = render_batch_text(results, title=f"PhishLens folder scan: {root}")
        if skipped:
            report += f"\nSkipped unreadable messages: {skipped}"
        self._set_output(report)
        self.evidence_var.set("Select a message to open its complete analysis report.")
        self._set_status(f"Scanned {len(results)} messages; skipped {skipped}")

    def _export_scan_csv(self) -> None:
        if not self._scan_results:
            messagebox.showinfo("PhishLens", "Run a folder scan before exporting a CSV report.")
            return
        selection = filedialog.asksaveasfilename(
            title="Export folder scan as CSV",
            defaultextension=".csv",
            initialfile="phishlens-folder-scan.csv",
            filetypes=[("CSV spreadsheet", "*.csv"), ("All files", "*.*")],
        )
        if not selection:
            return
        try:
            Path(selection).write_text(render_batch_csv(self._scan_results), encoding="utf-8-sig")
        except OSError as error:
            messagebox.showerror("PhishLens", f"Could not export CSV: {error}")
            return
        self._set_status(f"CSV folder report saved to {selection}")

    def _train_model(self) -> None:
        dataset = Path(self.train_dataset_var.get().strip())
        output_text = self.train_output_var.get().strip()
        output = Path(output_text) if output_text else Path()
        if not dataset.is_dir():
            messagebox.showerror("PhishLens", "Choose a valid dataset folder first.")
            return
        if not output_text or output.suffix.lower() != ".json":
            messagebox.showerror("PhishLens", "Choose a model output path ending in .json.")
            return
        try:
            validation_split = float(self.validation_split_var.get())
        except ValueError:
            messagebox.showerror("PhishLens", "Validation must be a number like 0.2.")
            return

        def train() -> tuple[Path, NaiveBayesModel, TrainingReport]:
            model, report = train_from_directory(dataset, validation_split=validation_split)
            model.save(output)
            return output, model, report

        self._run_task("Training the local model...", train, self._show_training_result)

    def _show_training_result(self, payload: object) -> None:
        if not isinstance(payload, tuple) or len(payload) != 3:
            raise GuiError("training returned an unexpected result")
        output, model, report = payload
        if not isinstance(output, Path) or not isinstance(model, NaiveBayesModel) or not isinstance(report, TrainingReport):
            raise GuiError("training returned invalid data")
        self.model_state = _ModelState(path=output, model=model)
        self.model_label_var.set(output.name)
        self.model_status_label.configure(foreground=self.SAFE)
        self.score_var.set("--")
        self.verdict_var.set("MODEL READY")
        self.verdict_value_label.configure(foreground=self.SAFE)
        self.signal_var.set(str(report.vocabulary_size))
        self.model_score_var.set("Trained")
        self._configure_tree("Status", "", "Training note", "")
        self._clear_tree()
        if report.warnings:
            for warning in report.warnings:
                self.results_tree.insert("", "end", values=("NOTICE", "", warning, ""), tags=("medium",))
        else:
            self.results_tree.insert("", "end", values=("OK", "", "No training warnings", ""), tags=("safe",))
        self._set_output(render_training_report(report, str(output)))
        self.evidence_var.set("The new model is loaded and ready for the next analysis.")
        self._set_status(f"Model trained and saved to {output}")
        messagebox.showinfo("PhishLens", f"Training complete.\nModel saved to:\n{output}")

    def _update_metrics(self, score: int, verdict: str, signals: int, result: AnalysisResult) -> None:
        self.score_var.set(f"{score}/100")
        self.verdict_var.set(verdict.upper())
        self.signal_var.set(str(signals))
        color = self.DANGER if verdict == "high-risk" else self.WARNING if verdict == "suspicious" else self.SAFE
        self.verdict_value_label.configure(foreground=color)
        self.score_value_label.configure(foreground=color)
        if result.model_prediction is None:
            self.model_score_var.set("Not loaded")
        else:
            self.model_score_var.set(f"{result.model_prediction.phishing_probability:.0%} phish")

    def _on_result_selected(self, _event: object) -> None:
        selected = self.results_tree.selection()
        if not selected:
            return
        payload = self._row_payload.get(selected[0])
        if isinstance(payload, Finding):
            self.evidence_var.set(payload.evidence)
        elif isinstance(payload, AnalysisResult):
            self.evidence_var.set(f"{payload.headers['from'] or '<missing sender>'} | {len(payload.findings)} signals")
            self._set_output(render_text(payload))
            self._update_metrics(payload.score, payload.verdict, len(payload.findings), payload)

    def _copy_report(self) -> None:
        if not self._displayed_report:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self._displayed_report)
        self._set_status("Report copied to the clipboard")

    def _save_report(self) -> None:
        if not self._displayed_report:
            return
        selection = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".txt",
            initialfile="phishlens-report.txt",
            filetypes=[("Text report", "*.txt"), ("All files", "*.*")],
        )
        if not selection:
            return
        try:
            Path(selection).write_text(self._displayed_report, encoding="utf-8")
        except OSError as error:
            messagebox.showerror("PhishLens", f"Could not save report: {error}")
            return
        self._set_status(f"Report saved to {selection}")


def launch_gui(initial_model_path: Path | None = None) -> None:
    try:
        root = tk.Tk()
    except Exception as error:  # pragma: no cover - depends on local Tk availability
        raise GuiError(f"desktop UI could not start: {error}") from error

    app = PhishLensApp(root, initial_model_path=initial_model_path)
    app.root.mainloop()


def main(argv: list[str] | None = None) -> int:
    _ = argv
    launch_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

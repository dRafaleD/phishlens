use eframe::egui::{
    self, Align, Button, CentralPanel, Color32, ComboBox, Context, Frame, Grid, Layout, Margin,
    ProgressBar, RichText, ScrollArea, SidePanel, Stroke, TextEdit, TopBottomPanel, Ui,
    ViewportBuilder,
};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([1024.0, 720.0])
            .with_title("Safe Malware Behavior Simulator"),
        ..Default::default()
    };

    eframe::run_native(
        "Safe Malware Behavior Simulator",
        options,
        Box::new(|cc| {
            configure_theme(&cc.egui_ctx);
            Ok(Box::<SimulatorApp>::default())
        }),
    )
}

fn configure_theme(ctx: &Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.visuals.window_fill = Color32::from_rgb(14, 18, 24);
    style.visuals.panel_fill = Color32::from_rgb(10, 13, 18);
    style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(18, 24, 32);
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(21, 28, 38);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(36, 50, 68);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(34, 77, 108);
    style.visuals.widgets.open.bg_fill = Color32::from_rgb(30, 43, 58);
    style.visuals.selection.bg_fill = Color32::from_rgb(52, 120, 172);
    style.visuals.extreme_bg_color = Color32::from_rgb(8, 11, 15);
    style.visuals.faint_bg_color = Color32::from_rgb(16, 21, 28);
    ctx.set_style(style);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    FileDropper,
    Persistence,
    Beaconing,
    ObfuscatedScript,
    MultiStageChain,
}

impl Scenario {
    const ALL: [Scenario; 5] = [
        Scenario::FileDropper,
        Scenario::Persistence,
        Scenario::Beaconing,
        Scenario::ObfuscatedScript,
        Scenario::MultiStageChain,
    ];

    fn label(self) -> &'static str {
        match self {
            Scenario::FileDropper => "File Dropper",
            Scenario::Persistence => "Persistence",
            Scenario::Beaconing => "Network Beaconing",
            Scenario::ObfuscatedScript => "Obfuscated Script",
            Scenario::MultiStageChain => "Multi-stage Chain",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Scenario::FileDropper => "Staged temp writes and follow-up execution",
            Scenario::Persistence => "Autorun and scheduled execution artifacts",
            Scenario::Beaconing => "Periodic outbound check-ins with jitter",
            Scenario::ObfuscatedScript => "Encoded script chains and string decoding",
            Scenario::MultiStageChain => "Launcher, extract, persist, beacon timeline",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Scenario::FileDropper => {
                "Simulates suspicious file writes, temp directory usage, and a follow-up process spawn."
            }
            Scenario::Persistence => {
                "Simulates startup registration attempts and scheduled execution without changing the host system."
            }
            Scenario::Beaconing => {
                "Simulates repeated outbound requests, randomized sleep intervals, and IOC-like logging."
            }
            Scenario::ObfuscatedScript => {
                "Simulates base64-heavy script content, string decoding, and suspicious interpreter chains."
            }
            Scenario::MultiStageChain => {
                "Simulates an initial launcher, payload extraction, persistence attempt, and beaconing in one timeline."
            }
        }
    }

    fn severity(self) -> &'static str {
        match self {
            Scenario::FileDropper => "Medium",
            Scenario::Persistence => "High",
            Scenario::Beaconing => "Medium",
            Scenario::ObfuscatedScript => "High",
            Scenario::MultiStageChain => "Critical",
        }
    }

    fn confidence(self) -> f32 {
        match self {
            Scenario::FileDropper => 0.62,
            Scenario::Persistence => 0.84,
            Scenario::Beaconing => 0.71,
            Scenario::ObfuscatedScript => 0.88,
            Scenario::MultiStageChain => 0.94,
        }
    }

    fn iocs(self) -> &'static [&'static str] {
        match self {
            Scenario::FileDropper => &[
                "File path: AppData\\Roaming\\Updater\\updater.dat",
                "Child process: rundll32.exe updater.dat,Start",
                "Temp artifact: cache.bin",
            ],
            Scenario::Persistence => &[
                "Autorun key: HKCU\\...\\Run\\Updater",
                "Task name: OneDrive Update Monitor",
                "Roaming binary: client.exe --background",
            ],
            Scenario::Beaconing => &[
                "Domain: cdn-assets-sync.example.test",
                "URI: /pixel.gif",
                "Pattern: jittered periodic POST",
            ],
            Scenario::ObfuscatedScript => &[
                "Interpreter chain: wscript -> powershell",
                "Encoded payload marker: -EncodedCommand",
                "Large base64 blob in script body",
            ],
            Scenario::MultiStageChain => &[
                "Launcher: signed_loader.exe",
                "Extracted payload: payload_01.tmp",
                "Check-in path: /tasks/checkin",
            ],
        }
    }

    fn findings(self) -> &'static [&'static str] {
        match self {
            Scenario::FileDropper => &[
                "Suspicious temp file creation",
                "User profile write outside normal app directory",
                "Follow-up execution through LOLBIN-like process",
            ],
            Scenario::Persistence => &[
                "Autorun persistence attempt",
                "Scheduled execution artifact",
                "Background copy inside roaming profile",
            ],
            Scenario::Beaconing => &[
                "Periodic outbound network pattern",
                "Consistent destination IOC",
                "Beacon jitter behavior",
            ],
            Scenario::ObfuscatedScript => &[
                "Encoded command chain",
                "High-entropy/base64 content",
                "Interpreter-to-interpreter execution path",
            ],
            Scenario::MultiStageChain => &[
                "Multi-stage execution timeline",
                "Payload extraction behavior",
                "Persistence plus network activity correlation",
            ],
        }
    }

    fn events(self) -> &'static [&'static str] {
        match self {
            Scenario::FileDropper => &[
                "powershell.exe spawned by invoice_viewer.exe",
                "WriteFile: C:\\Users\\analyst\\AppData\\Local\\Temp\\cache.bin",
                "WriteFile: C:\\Users\\analyst\\AppData\\Roaming\\Updater\\updater.dat",
                "ProcessCreate: rundll32.exe updater.dat,Start",
                "DeleteFile: C:\\Users\\analyst\\AppData\\Local\\Temp\\cache.bin",
            ],
            Scenario::Persistence => &[
                "ProcessCreate: office_macro_runner.exe",
                "RegistrySetValue (simulated): HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "ScheduledTaskCreate (simulated): OneDrive Update Monitor",
                "CopyFile: C:\\Users\\analyst\\AppData\\Roaming\\Updater\\client.exe",
                "ProcessCreate: client.exe --background",
            ],
            Scenario::Beaconing => &[
                "ProcessCreate: service_host_clone.exe",
                "DNSQuery: cdn-assets-sync.example.test",
                "HTTP POST: /pixel.gif (224 bytes)",
                "Sleep: jittered 37s",
                "HTTP POST: /pixel.gif (228 bytes)",
            ],
            Scenario::ObfuscatedScript => &[
                "ProcessCreate: wscript.exe invoice.js",
                "LargeBase64BlobDetected: 1876 chars",
                "StringDecodeLoop: 14 iterations",
                "ProcessCreate: powershell.exe -EncodedCommand <redacted>",
                "WriteFile: C:\\Users\\analyst\\AppData\\Local\\Temp\\stage.txt",
            ],
            Scenario::MultiStageChain => &[
                "ProcessCreate: signed_loader.exe",
                "ResourceExtract: payload_01.tmp",
                "RegistrySetValue (simulated): HKCU\\...\\Run\\SignedUpdate",
                "ProcessCreate: payload_01.tmp --service",
                "HTTP POST: /tasks/checkin (312 bytes)",
            ],
        }
    }

    fn event_kind_breakdown(self) -> (usize, usize, usize) {
        match self {
            Scenario::FileDropper => (2, 1, 2),
            Scenario::Persistence => (1, 2, 2),
            Scenario::Beaconing => (1, 3, 1),
            Scenario::ObfuscatedScript => (2, 0, 3),
            Scenario::MultiStageChain => (2, 2, 1),
        }
    }
}

struct SimulatorApp {
    scenario: Scenario,
    telemetry: String,
    running: bool,
    started_at: Option<Instant>,
    emitted_events: usize,
    auto_scroll: bool,
}

impl Default for SimulatorApp {
    fn default() -> Self {
        Self {
            scenario: Scenario::MultiStageChain,
            telemetry: String::new(),
            running: false,
            started_at: None,
            emitted_events: 0,
            auto_scroll: true,
        }
    }
}

impl SimulatorApp {
    fn reset(&mut self) {
        self.telemetry.clear();
        self.running = false;
        self.started_at = None;
        self.emitted_events = 0;
    }

    fn start(&mut self) {
        self.reset();
        self.running = true;
        self.started_at = Some(Instant::now());
        self.push_line("== Safe simulation started ==");
        self.push_line("No real malware behavior is performed on this machine.");
    }

    fn push_line(&mut self, line: &str) {
        let _ = writeln!(self.telemetry, "{line}");
    }

    fn progress(&self) -> f32 {
        let total = self.scenario.events().len().max(1) as f32;
        (self.emitted_events as f32 / total).clamp(0.0, 1.0)
    }

    fn elapsed_label(&self) -> String {
        self.started_at
            .map(|started| {
                let elapsed = started.elapsed();
                format!(
                    "{:02}:{:02}",
                    elapsed.as_secs() / 60,
                    elapsed.as_secs() % 60
                )
            })
            .unwrap_or_else(|| "00:00".to_owned())
    }

    fn tick(&mut self) {
        if !self.running {
            return;
        }

        let Some(started_at) = self.started_at else {
            return;
        };

        let elapsed = started_at.elapsed();
        let events = self.scenario.events();
        let next_index = (elapsed.as_millis() / 900) as usize;

        while self.emitted_events <= next_index && self.emitted_events < events.len() {
            let line = format!(
                "[{:>5}.{:03}s] {}",
                elapsed.as_secs(),
                elapsed.subsec_millis(),
                events[self.emitted_events]
            );
            self.push_line(&line);
            self.emitted_events += 1;
        }

        if self.emitted_events >= events.len() {
            self.push_line("== Simulation completed ==");
            self.running = false;
        }
    }
}

impl eframe::App for SimulatorApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.tick();

        if self.running {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        TopBottomPanel::top("top_bar")
            .frame(
                Frame::default()
                    .fill(Color32::from_rgb(12, 16, 23))
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| self.render_top_bar(ui));

        SidePanel::left("scenario_panel")
            .default_width(320.0)
            .resizable(true)
            .frame(
                Frame::default()
                    .fill(Color32::from_rgb(11, 15, 21))
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| self.render_left_panel(ui));

        CentralPanel::default()
            .frame(
                Frame::default()
                    .fill(Color32::from_rgb(8, 11, 16))
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| self.render_main_panel(ui));
    }
}

impl SimulatorApp {
    fn render_top_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(RichText::new("Safe Malware Behavior Simulator").size(24.0));
                ui.label(
                    RichText::new(
                        "A safe desktop harness for validating malware-analysis workflows.",
                    )
                    .color(Color32::from_rgb(171, 187, 205)),
                );
            });

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                pill(ui, self.scenario.severity(), severity_color(self.scenario));
                ui.add_space(8.0);
                pill(
                    ui,
                    if self.running { "Running" } else { "Ready" },
                    status_color(self.running),
                );
            });
        });
    }

    fn render_left_panel(&mut self, ui: &mut Ui) {
        card_frame().show(ui, |ui| {
            ui.label(section_title("Scenario Control"));
            ui.add_space(8.0);

            let previous = self.scenario;
            ComboBox::from_label("Behavior profile")
                .selected_text(self.scenario.label())
                .width(ui.available_width() - 12.0)
                .show_ui(ui, |ui| {
                    for scenario in Scenario::ALL {
                        ui.selectable_value(&mut self.scenario, scenario, scenario.label());
                    }
                });

            if self.scenario != previous {
                self.reset();
            }

            ui.add_space(8.0);
            ui.label(RichText::new(self.scenario.subtitle()).strong());
            ui.label(
                RichText::new(self.scenario.description()).color(Color32::from_rgb(171, 187, 205)),
            );
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.running,
                        Button::new(RichText::new("Run Simulation").strong()),
                    )
                    .clicked()
                {
                    self.start();
                }

                if ui.button("Reset").clicked() {
                    self.reset();
                }
            });

            ui.checkbox(&mut self.auto_scroll, "Auto-scroll telemetry");
        });

        ui.add_space(12.0);

        card_frame().show(ui, |ui| {
            ui.label(section_title("Indicators"));
            ui.add_space(8.0);
            for ioc in self.scenario.iocs() {
                ui.label(RichText::new(format!("- {ioc}")).monospace());
            }
        });

        ui.add_space(12.0);

        card_frame().show(ui, |ui| {
            ui.label(section_title("Detection Logic"));
            ui.add_space(8.0);
            for finding in self.scenario.findings() {
                ui.label(
                    RichText::new(format!("- {finding}")).color(Color32::from_rgb(209, 219, 232)),
                );
            }
        });
    }

    fn render_main_panel(&mut self, ui: &mut Ui) {
        Grid::new("summary_grid")
            .num_columns(4)
            .spacing([12.0, 12.0])
            .show(ui, |ui| {
                stat_card(
                    ui,
                    "Events Emitted",
                    &self.emitted_events.to_string(),
                    "live",
                );
                stat_card(
                    ui,
                    "Elapsed",
                    &self.elapsed_label(),
                    if self.running { "active" } else { "idle" },
                );
                stat_card(
                    ui,
                    "Confidence",
                    &format!("{:.0}%", self.scenario.confidence() * 100.0),
                    "score",
                );
                stat_card(
                    ui,
                    "Profile",
                    self.scenario.label(),
                    self.scenario.severity(),
                );
                ui.end_row();
            });

        ui.add_space(14.0);

        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(section_title("Execution Timeline"));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{:.0}% complete", self.progress() * 100.0))
                            .color(Color32::from_rgb(159, 177, 198)),
                    );
                });
            });

            ui.add_space(6.0);
            ui.add(
                ProgressBar::new(self.progress())
                    .desired_width(f32::INFINITY)
                    .fill(Color32::from_rgb(59, 140, 198))
                    .show_percentage(),
            );
        });

        ui.add_space(14.0);

        ui.columns(2, |columns| {
            card_frame().show(&mut columns[0], |ui| {
                ui.label(section_title("Telemetry Stream"));
                ui.add_space(8.0);
                ScrollArea::vertical()
                    .stick_to_bottom(self.auto_scroll)
                    .show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(&mut self.telemetry)
                                .desired_rows(24)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace)
                                .interactive(false),
                        );
                    });
            });

            card_frame().show(&mut columns[1], |ui| {
                ui.label(section_title("Analysis Snapshot"));
                ui.add_space(8.0);

                let (process_count, network_count, file_count) = self.scenario.event_kind_breakdown();
                small_metric(ui, "Process", process_count, Color32::from_rgb(91, 189, 146));
                small_metric(ui, "Network", network_count, Color32::from_rgb(82, 164, 223));
                small_metric(ui, "File/Registry", file_count, Color32::from_rgb(230, 162, 92));

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(12.0);
                ui.label(section_title("Expected Findings"));
                ui.add_space(6.0);

                for finding in self.scenario.findings() {
                    ui.horizontal(|ui| {
                        ui.colored_label(Color32::from_rgb(248, 114, 114), ">");
                        ui.label(finding);
                    });
                }

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(12.0);
                ui.label(section_title("Safety Guardrail"));
                ui.label(
                    RichText::new(
                        "All activity shown here is synthetic log generation inside the app. No persistence, file drops, registry edits, or network traffic are executed on the host.",
                    )
                    .color(Color32::from_rgb(171, 187, 205)),
                );
            });
        });
    }
}

fn card_frame() -> Frame {
    Frame::default()
        .fill(Color32::from_rgb(16, 21, 29))
        .stroke(Stroke::new(1.0, Color32::from_rgb(38, 48, 62)))
        .corner_radius(10.0)
        .inner_margin(Margin::same(16))
}

fn section_title(text: &str) -> RichText {
    RichText::new(text)
        .size(17.0)
        .strong()
        .color(Color32::from_rgb(236, 243, 252))
}

fn severity_color(scenario: Scenario) -> Color32 {
    match scenario {
        Scenario::FileDropper | Scenario::Beaconing => Color32::from_rgb(229, 162, 87),
        Scenario::Persistence | Scenario::ObfuscatedScript => Color32::from_rgb(233, 102, 102),
        Scenario::MultiStageChain => Color32::from_rgb(192, 70, 70),
    }
}

fn status_color(running: bool) -> Color32 {
    if running {
        Color32::from_rgb(83, 181, 136)
    } else {
        Color32::from_rgb(92, 112, 135)
    }
}

fn pill(ui: &mut Ui, text: &str, color: Color32) {
    Frame::default()
        .fill(color.gamma_multiply(0.22))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.8)))
        .corner_radius(999.0)
        .inner_margin(Margin::symmetric(12, 6))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).strong());
        });
}

fn stat_card(ui: &mut Ui, title: &str, value: &str, caption: &str) {
    Frame::default()
        .fill(Color32::from_rgb(16, 21, 29))
        .stroke(Stroke::new(1.0, Color32::from_rgb(38, 48, 62)))
        .corner_radius(10.0)
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.label(RichText::new(title).color(Color32::from_rgb(156, 173, 193)));
            ui.add_space(8.0);
            ui.label(RichText::new(value).size(24.0).strong());
            ui.label(RichText::new(caption).color(Color32::from_rgb(103, 122, 146)));
        });
}

fn small_metric(ui: &mut Ui, label: &str, count: usize, color: Color32) {
    ui.horizontal(|ui| {
        ui.colored_label(color, "[]");
        ui.label(label);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(count.to_string()).strong());
        });
    });
}

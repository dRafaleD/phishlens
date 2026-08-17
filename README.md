# Safe Malware Behavior Simulator

Safe Malware Behavior Simulator is a defensive, educational Rust desktop app
for demonstrating suspicious telemetry patterns without creating or executing
real malware.

It is designed for:

- blue-team demos
- malware-analysis training
- SOC workflow practice
- UI/UX experiments for detection tooling
- classroom-safe behavior simulation

## Why this project is GitHub-friendly

This repository stays on the safe side of cybersecurity work:

- no real payload execution
- no registry modification
- no persistence on the host
- no actual file dropping
- no live network traffic
- no exploit or offensive capability

Everything shown in the interface is synthetic telemetry rendered inside the
application.

## Features

- desktop UI built with `egui` and `eframe`
- selectable suspicious behavior profiles
- synthetic execution timeline
- IOC-style indicators
- expected detection findings
- safe telemetry stream for analyst training

## Included simulation profiles

- `File Dropper`
- `Persistence`
- `Network Beaconing`
- `Obfuscated Script`
- `Multi-stage Chain`

## Tech stack

- Rust
- `egui`
- `eframe`

## Local development

### Prerequisites

- Rust toolchain
- Cargo
- On Windows, Microsoft C++ build tools may be required by GUI dependencies

### Run

```powershell
cargo run
```

### Format

```powershell
cargo fmt
```

## Windows build note

On this machine, dependency resolution succeeded, but native compilation was
previously blocked because `link.exe` was not available on `PATH`.

Install one of the following if you hit that issue:

- Visual Studio Build Tools with the `Desktop development with C++` workload
- Visual Studio Community with C++ tooling enabled

Then run:

```powershell
cargo run
```

## Roadmap

- export simulated telemetry to JSON
- add Sigma-like rule preview for each scenario
- add MITRE ATT&CK-style mappings
- add timeline filters and severity sorting
- package Windows releases for GitHub Releases

## Safe scope

This project will not accept features that:

- execute real suspicious commands
- drop or unpack real binaries
- alter registry keys or scheduled tasks
- create persistence on the host
- contact live remote infrastructure
- simulate credential theft or evasion in a real environment

## License

MIT

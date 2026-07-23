# Agent discovery

Discovery reads versioned YAML signatures for known executables, process patterns, environment markers, parent processes, install paths, and config paths. Multiple independent observations combine through a bounded score.

Attribution levels are unknown, weak, probable, and strong. Process evidence is capped at strong; confirmed is reserved for structured native adapter requests. Environment markers cannot classify an agent by themselves.

Live process capture is optional (`.[capture]`) and best effort across permission boundaries. Command lines and environment values may be used transiently for matching but are never copied into telemetry. `ProcessRecord.to_ecs` exports PID, name, executable, working directory, and safe parent metadata only.

`watchmyai discover` emits inventory/session evidence. It does not authorize, block, or claim that a child effect was caused by an AI model.

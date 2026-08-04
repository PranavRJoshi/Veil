# Example configs

Each file is a ready-to-run Veil trace for one way of observing an
application (modify flags such as PID accordingly). Load one with `--config`:

```bash
sudo ./bin/veil --config examples/network-audit.yaml
```

A config file governs the modules and their output; the file's advantage over
the command line is that each module gets its own filters, which a single
shared set of CLI flags cannot express. See the [Configuration File](../docs/USAGE.md#configuration-file)
section for the full schema.

| File | Question it answers |
|---|---|
| [incident-triage.yaml](incident-triage.yaml) | What is one suspect PID doing across syscalls, files, and network at once? |
| [syscall-profile.yaml](syscall-profile.yaml) | Which syscalls does a service spend itself on? |
| [network-audit.yaml](network-audit.yaml) | A compact JSON log of TCP connections, ready for `jq` or a shipper. |
| [io-hotspots.yaml](io-hotspots.yaml) | Which files see the most read/write activity? |
| [scheduler-oncpu.yaml](scheduler-oncpu.yaml) | Which tasks are scheduled most often on a busy core? |
A
| [uprobe-latency.yaml](uprobe-latency.yaml) | How long does a hot userspace function take in a running process? |

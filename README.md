# Ragna-Pröc

A daemon in Rust to terminate executables that are running on the login node
when they really should go on the job queue.

## Build

```bash
cargo build --release 
```

## Run

1) Edit ragnaproc.yaml

```yaml
minuser: 1000 # The minimum UID - processes of users <PID are not signalled
maxuser: null # The maximum UID - processes of users >PID are not signalled
maxtime: 300 # Maximum CPU time (kernel + user) the process is allowed as a grace period - in seconds
maxrss: 200000000 # Maximum RSS the process is allowed - in pages
poll: 5 # How often to poll /proc - in seconds
deny: # A list of patterns to match processes
  - pattern: "^/mnt/picea/storage/Modules/.*"
  - pattern: "^/usr/bin/rsync$"
  - pattern: "^/opt/zoom/zoom$"
```
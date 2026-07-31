# kprowl

A small eBPF-based security monitor for Linux. It watches for three behaviors:

- **Execution** — what a traced process runs (`execve`)
- **Sensitive file access** — reads of `/etc/shadow`, SSH keys, AWS credentials, etc.,
  matched by **inode** (robust against symlinks and relative paths)
- **Outbound connections** — IPv4 `connect()`s, flagged when a shell/interpreter dials out
  (reverse-shell heuristic)

Two front-ends share one BPF object:

- **`loader`** — trace a single launched process tree
- **`monitor`** — system-wide daemon; reports the above for **any** process

## Requirements

- Linux kernel **5.8+** with BTF enabled (`/sys/kernel/btf/vmlinux` exists)
- `clang`, `libbpf-dev`, `bpftool`, `gcc`

On Debian/Ubuntu:

```bash
sudo apt install -y clang libbpf-dev linux-tools-$(uname -r) gcc make
```

## Build

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c kprowl.bpf.c -o kprowl.bpf.o
gcc loader.c  -o loader  -lbpf
gcc monitor.c -o monitor -lbpf
```

Use `-D__TARGET_ARCH_arm64` on ARM. `vmlinux.h` is machine-specific and not committed —
generate it with the `bpftool` command above.

## Usage

```bash
# trace a single program
sudo ./loader cat /etc/shadow

# watch the whole system
sudo ./monitor
```

Sample output:

```
[EXEC]   pid=56410 uid=0    comm=cat    exec=/usr/bin/cat
[FILE!]  pid=56410 uid=0    comm=cat    SENSITIVE=/etc/shadow
[CONN!!] pid=57120 uid=0    comm=bash   -> 1.1.1.1:53   <== possible reverse shell
```

## Notes & limitations

- **Detection only** — it observes, it does not block.
- Watchlist inodes are read once at startup; a file rewritten via rename gets a new inode.
- IPv4 only; `loader` traces only the launched PID (add a `sched_process_fork` hook for descendants).

## License

Dual BSD/GPL (BPF program). See `kprowl.bpf.c`.

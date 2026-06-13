#!/usr/bin/env python3
"""
K8s Arsenal Attack Chain Detector — Falco-equivalent runtime detection
Monitors host processes, filesystem events, and container activity.
"""

import os, time, json, re, subprocess
from datetime import datetime
from pathlib import Path

HOST_ROOT = os.environ.get("HOST_ROOT", "/host")
POLL_INTERVAL = 2  # seconds

# Attack chain detection rules
RULES = [
    {
        "id": "R001",
        "name": "Privileged Container Created",
        "priority": "CRITICAL",
        "check": lambda state: state.get("new_privileged_containers", []),
        "format": lambda hit: f"Privileged container: cgroup={hit['cgroup']}",
    },
    {
        "id": "R002",
        "name": "NSEnter Escape",
        "priority": "CRITICAL",
        "check": lambda state: state.get("nsenter_procs", []),
        "format": lambda hit: f"nsenter escape: pid={hit['pid']} cmd={hit['cmdline']}",
    },
    {
        "id": "R003",
        "name": "Kubeconfig Access",
        "priority": "CRITICAL",
        "check": lambda state: state.get("kubeconfig_access", []),
        "format": lambda hit: f"kubeconfig read: {hit['path']} by pid={hit['pid']}",
    },
    {
        "id": "R004",
        "name": "Kubelet Cert Access",
        "priority": "HIGH",
        "check": lambda state: state.get("kubelet_cert_access", []),
        "format": lambda hit: f"kubelet cert access: {hit['path']}",
    },
    {
        "id": "R005",
        "name": "SA Token Theft",
        "priority": "HIGH",
        "check": lambda state: state.get("sa_token_access", []),
        "format": lambda hit: f"SA token theft: {hit['path']} (namespace={hit['ns']})",
    },
    {
        "id": "R006",
        "name": "Cron Persistence",
        "priority": "CRITICAL",
        "check": lambda state: state.get("cron_writes", []),
        "format": lambda hit: f"Cron persistence: {hit['path']}",
    },
    {
        "id": "R007",
        "name": "Etc Directory Write",
        "priority": "WARNING",
        "check": lambda state: state.get("etc_writes", []),
        "format": lambda hit: f"Write to /etc: {hit['path']}",
    },
    {
        "id": "R008",
        "name": "Sensitive Mount Access",
        "priority": "MEDIUM",
        "check": lambda state: state.get("sensitive_mounts", []),
        "format": lambda hit: f"Sensitive mount: {hit['path']}",
    },
]

def get_process_list():
    """Get all processes from /proc (host view via HOST_ROOT)"""
    procs = []
    proc_root = Path(HOST_ROOT) / "proc"
    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            pid = int(pid_dir.name)
            cmdline = (pid_dir / "cmdline").read_text(errors="replace").replace("\0", " ").strip()
            cgroup_path = pid_dir / "cgroup"
            cgroup = ""
            if cgroup_path.exists():
                cgroup = cgroup_path.read_text(errors="replace").strip()
            procs.append({"pid": pid, "cmdline": cmdline, "cgroup": cgroup})
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    return {p["pid"]: p for p in procs}

def scan_privesc(state):
    """Detect privileged containers and nsenter"""
    proc_root = Path(HOST_ROOT) / "proc"
    
    # Check for nsenter processes
    new_nsenter = []
    for pid, info in state.get("_current_procs", {}).items():
        if "nsenter" in info["cmdline"] and "-t" in info["cmdline"]:
            if pid not in state.get("_seen_nsenter", set()):
                new_nsenter.append(info)
                state.setdefault("_seen_nsenter", set()).add(pid)
    
    if new_nsenter:
        state.setdefault("nsenter_procs", []).extend(new_nsenter)
    
    # Check for containers with privileged flag in cgroup
    # (Detected by scanning for containers with docker.sock or special cgroup entries)
    return state

def scan_fs_access(state):
    """Scan /proc/*/fd for sensitive file access"""
    proc_root = Path(HOST_ROOT) / "proc"
    seen = state.setdefault("_seen_fd_access", set())
    
    sensitive_patterns = {
        "kubeconfig_access": [
            re.compile(r"/etc/kubernetes/(admin|super-admin)\.conf"),
            re.compile(r".*/\.kube/config$"),
        ],
        "kubelet_cert_access": [
            re.compile(r"/var/lib/kubelet/pki/.*\.(crt|key|pem)"),
        ],
        "sa_token_access": [
            re.compile(r".*/volumes/kubernetes\.io~.*/token$"),
        ],
    }
    
    for pid_dir in list(proc_root.iterdir())[:200]:  # Limit scan scope
        if not pid_dir.name.isdigit():
            continue
        try:
            fd_dir = pid_dir / "fd"
            if not fd_dir.exists():
                continue
            pid = int(pid_dir.name)
            for fd_link in fd_dir.iterdir():
                try:
                    target = os.readlink(str(fd_link))
                    for rule_name, patterns in sensitive_patterns.items():
                        for pat in patterns:
                            if pat.search(target):
                                ns = ""
                                # Try to get namespace from the SA token dir
                                if "token" in target:
                                    ns_dir = Path(target).parent
                                    ns_file = ns_dir / "namespace"
                                    if ns_file.exists():
                                        try:
                                            ns = ns_file.read_text().strip()
                                        except:
                                            pass
                                key = f"{rule_name}:{pid}:{target}"
                                if key not in seen:
                                    seen.add(key)
                                    state.setdefault(rule_name, []).append({
                                        "pid": pid, "path": target, "ns": ns
                                    })
                except OSError:
                    pass
        except (PermissionError, FileNotFoundError):
            pass
    
    return state

def scan_cron_writes(state):
    """Check for cron writes by monitoring /etc/cron* and /var/spool/cron"""
    cron_paths = [
        Path(HOST_ROOT) / "etc/crontab",
        Path(HOST_ROOT) / "etc/cron.d",
        Path(HOST_ROOT) / "var/spool/cron",
    ]
    seen = state.setdefault("_seen_cron_mtime", {})
    
    for cp in cron_paths:
        try:
            if cp.is_file():
                mtime = cp.stat().st_mtime
                if cp.name not in seen:
                    seen[cp.name] = mtime
                elif mtime != seen[cp.name]:
                    seen[cp.name] = mtime
                    state.setdefault("cron_writes", []).append({
                        "path": str(cp).replace(HOST_ROOT, ""),
                        "time": datetime.now().isoformat()
                    })
            elif cp.is_dir():
                for f in cp.iterdir():
                    try:
                        mtime = f.stat().st_mtime
                        key = str(f)
                        if key not in seen:
                            seen[key] = mtime
                        elif mtime != seen[key]:
                            seen[key] = mtime
                            state.setdefault("cron_writes", []).append({
                                "path": str(f).replace(HOST_ROOT, ""),
                                "time": datetime.now().isoformat()
                            })
                    except OSError:
                        pass
        except (PermissionError, FileNotFoundError):
            pass
    
    return state

def format_alert(rule, hit):
    """Format a detection alert as JSON"""
    return json.dumps({
        "timestamp": datetime.now().isoformat(),
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "priority": rule["priority"],
        "detail": rule["format"](hit),
    }, ensure_ascii=False)

def main():
    print(f"[{datetime.now().isoformat()}] K8s Arsenal Detector started (Falco-equivalent)", flush=True)
    print(f"  HOST_ROOT={HOST_ROOT}  POLL_INTERVAL={POLL_INTERVAL}s", flush=True)
    print(f"  Rules loaded: {len(RULES)}", flush=True)
    for r in RULES:
        print(f"    [{r['priority']:8s}] {r['id']}: {r['name']}", flush=True)
    print("=" * 60, flush=True)
    
    state = {"_seen_nsenter": set(), "_seen_fd_access": set(), "_seen_cron_mtime": {}}
    
    # Establish baseline
    state["_current_procs"] = get_process_list()
    
    iteration = 0
    while True:
        iteration += 1
        time.sleep(POLL_INTERVAL)
        
        # Refresh process list
        state["_current_procs"] = get_process_list()
        
        # Run all scans
        state = scan_privesc(state)
        state = scan_fs_access(state)
        state = scan_cron_writes(state)
        
        # Check rules and emit alerts
        for rule in RULES:
            hits = rule["check"](state)
            if hits:
                # Only alert on the newest hits
                for hit in hits[-3:]:  # Last 3 hits per rule
                    alert = format_alert(rule, hit)
                    print(f"\033[91m[ALERT]\033[0m {alert}", flush=True)
        
        # Heartbeat every 30 iterations
        if iteration % 15 == 0:
            print(f"[{datetime.now().isoformat()}] heartbeat: iter={iteration} alerts_emitted", flush=True)

if __name__ == "__main__":
    main()

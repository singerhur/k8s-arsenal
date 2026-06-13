#!/usr/bin/env python3
"""
K8s Arsenal Detector v2 — Uses Kubernetes API + filesystem monitoring
"""
import os, time, json, re, subprocess
from datetime import datetime, timezone
from pathlib import Path
from kubernetes import client, config, watch

HOST_ROOT = os.environ.get("HOST_ROOT", "/host")
POLL_INTERVAL = 1

ALERTS = []

def alert(rule_id, name, priority, detail):
    a = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_id": rule_id, "rule_name": name,
        "priority": priority, "detail": detail,
    }, ensure_ascii=False)
    print(f"[ALERT] {a}", flush=True)
    ALERTS.append(a)

def watch_privileged_pods():
    """Watch K8s API for new privileged pods"""
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    w = watch.Watch()
    print("[INFO] Starting privileged pod watcher...", flush=True)
    
    for event in w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=3600):
        pod = event['object']
        if event['type'] != 'ADDED':
            continue
        
        for container in pod.spec.containers:
            sc = container.security_context
            if sc and sc.privileged:
                alert("R001", "Privileged Container Created", "CRITICAL",
                      f"Pod={pod.metadata.namespace}/{pod.metadata.name} "
                      f"Container={container.name} Image={container.image} "
                      f"hostPID={pod.spec.host_pid} hostNetwork={pod.spec.host_network} "
                      f"hostIPC={pod.spec.host_ipc}")

def monitor_crontab():
    """Monitor /etc/cron.d for new files"""
    cron_d = Path(HOST_ROOT) / "etc/cron.d"
    known = set()
    
    if cron_d.exists():
        for f in cron_d.iterdir():
            known.add(f.name)
    
    print(f"[INFO] Crontab monitor started. Baseline: {len(known)} files", flush=True)
    
    while True:
        time.sleep(POLL_INTERVAL)
        if not cron_d.exists():
            continue
        try:
            current = set(f.name for f in cron_d.iterdir())
            new = current - known
            for fname in new:
                fpath = cron_d / fname
                try:
                    content = fpath.read_text()[:200]
                except:
                    content = "(unreadable)"
                alert("R006", "Cron Persistence", "CRITICAL",
                      f"New crontab file: /etc/cron.d/{fname} content={content.strip()}")
            known = current
        except PermissionError:
            pass

def monitor_kubelet_pods():
    """Monitor /var/lib/kubelet/pods for new privileged pod directories"""
    pods_dir = Path(HOST_ROOT) / "var/lib/kubelet/pods"
    known = set()
    
    if pods_dir.exists():
        for d in pods_dir.iterdir():
            if d.is_dir():
                known.add(d.name)
    
    print(f"[INFO] Kubelet pod monitor started. Baseline: {len(known)} pods", flush=True)
    
    while True:
        time.sleep(POLL_INTERVAL)
        if not pods_dir.exists():
            continue
        try:
            current = set(d.name for d in pods_dir.iterdir() if d.is_dir())
            new = current - known
            for pod_uid in new:
                alert("R008", "New Pod Directory", "MEDIUM",
                      f"New pod UID in kubelet: {pod_uid}")
            known = current
        except PermissionError:
            pass

def monitor_kubeconfig_access():
    """Check if admin kubeconfig was accessed (check atime if available)"""
    kubeconfig = Path(HOST_ROOT) / "etc/kubernetes/admin.conf"
    last_mtime = None
    
    if kubeconfig.exists():
        last_mtime = kubeconfig.stat().st_mtime
        last_atime = kubeconfig.stat().st_atime
    
    print(f"[INFO] Kubeconfig monitor started. mtime={last_mtime}", flush=True)
    
    while True:
        time.sleep(POLL_INTERVAL * 2)
        if not kubeconfig.exists():
            continue
        try:
            st = kubeconfig.stat()
            if last_mtime and st.st_mtime != last_mtime:
                alert("R003", "Kubeconfig Modification", "CRITICAL",
                      f"admin.conf modified! old_mtime={last_mtime} new_mtime={st.st_mtime}")
                last_mtime = st.st_mtime
        except (PermissionError, FileNotFoundError):
            pass

def monitor_nsenter():
    """Poll for nsenter processes (fast polling)"""
    seen = set()
    while True:
        time.sleep(0.3)  # Fast poll
        try:
            proc_root = Path(HOST_ROOT) / "proc"
            for pid_dir in list(proc_root.iterdir()):
                if not pid_dir.name.isdigit():
                    continue
                pid = int(pid_dir.name)
                try:
                    cmdline = (pid_dir / "cmdline").read_text(errors="replace").replace("\0", " ").strip()
                except:
                    continue
                if "nsenter" in cmdline and "-t" in cmdline and pid not in seen:
                    seen.add(pid)
                    alert("R002", "NSEnter Escape", "CRITICAL",
                          f"nsenter detected: PID={pid} cmdline={cmdline[:200]}")
        except (PermissionError, OSError):
            pass

def monitor_sa_token_access():
    """Check for new SA token files that indicate theft activity"""
    # This is harder to detect without catching the actual access
    # Instead, monitor for suspicious process patterns
    pass

import threading

def main():
    print(f"[{datetime.now().isoformat()}] K8s Arsenal Detector v2 started", flush=True)
    print(f"  HOST_ROOT={HOST_ROOT}  Multi-threaded monitoring", flush=True)
    print("=" * 60, flush=True)
    
    threads = [
        threading.Thread(target=watch_privileged_pods, daemon=True),
        threading.Thread(target=monitor_crontab, daemon=True),
        threading.Thread(target=monitor_kubelet_pods, daemon=True),
        threading.Thread(target=monitor_nsenter, daemon=True),
        threading.Thread(target=monitor_kubeconfig_access, daemon=True),
    ]
    
    for t in threads:
        t.start()
    
    # Keep alive + heartbeat
    i = 0
    while True:
        time.sleep(10)
        i += 1
        # Print summary
        for alert_json in ALERTS[-5:]:
            pass
        ALERTS.clear()
        print(f"[{datetime.now().isoformat()}] heartbeat: {i*10}s uptime, threads alive", flush=True)

if __name__ == "__main__":
    main()

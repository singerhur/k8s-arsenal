"""Scenario C: 供应链权限坍塌 — minikube 环境部署脚本

部署三个 Namespace 及相关 RBAC，构造跨越 5 层信任边界的权限坍塌链。
"""

import subprocess, sys, tempfile, os

def kubectl_apply(yaml_str: str):
    """通过临时文件 kubectl apply，避免 PowerShell escaping 问题"""
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.yaml', delete=False, encoding='utf-8'
    ) as f:
        f.write(yaml_str)
        tmp = f.name
    try:
        r = subprocess.run(
            f'kubectl apply -f {tmp}',
            shell=True, capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"  [FAIL]\n  stderr: {r.stderr.strip()}")
            sys.exit(1)
        return r.stdout
    finally:
        os.unlink(tmp)

print("=" * 60)
print("  Scenario C: 部署供应链权限坍塌环境")
print("=" * 60)

# ── Step 1: Create Namespaces ──
print("\n[1/5] Creating Namespaces...")
for ns in ["ci-ns", "prod-ns", "monitoring-ns"]:
    yaml = f"""apiVersion: v1
kind: Namespace
metadata:
  name: {ns}
"""
    kubectl_apply(yaml)
print("  ci-ns, prod-ns, monitoring-ns created.")

# ── Step 2: Create ServiceAccounts ──
print("\n[2/5] Creating ServiceAccounts...")
for sa, ns in [("ci-pipeline-sa", "ci-ns"),
               ("prod-app-sa", "prod-ns"),
               ("monitoring-operator-sa", "monitoring-ns")]:
    yaml = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: {sa}
  namespace: {ns}
"""
    kubectl_apply(yaml)
print("  ci-pipeline-sa, prod-app-sa, monitoring-operator-sa created.")

# ── Step 3: RBAC — build the permission collapse chain ──
print("\n[3/5] Deploying RBAC rules...")

# E1: ci-pipeline-sa can create deployments in prod-ns (GitOps deploy)
kubectl_apply("""apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ci-deployer
  namespace: prod-ns
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["create", "get", "list", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["services", "configmaps"]
  verbs: ["create", "get", "list", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ci-deployer-binding
  namespace: prod-ns
subjects:
- kind: ServiceAccount
  name: ci-pipeline-sa
  namespace: ci-ns
roleRef:
  kind: Role
  name: ci-deployer
  apiGroup: rbac.authorization.k8s.io
""")

# E2: prod-app-sa can read monitoring-ns secrets (cross-namespace RBAC trust)
kubectl_apply("""apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: monitoring-reader
  namespace: monitoring-ns
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: monitoring-reader-binding
  namespace: monitoring-ns
subjects:
- kind: ServiceAccount
  name: prod-app-sa
  namespace: prod-ns
roleRef:
  kind: Role
  name: monitoring-reader
  apiGroup: rbac.authorization.k8s.io
""")

# E3: monitoring-operator-sa can impersonate kubelet (ClusterRole!)
kubectl_apply("""apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubelet-impersonator
rules:
- apiGroups: [""]
  resources: ["users"]
  verbs: ["impersonate"]
  resourceNames: ["system:node:*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubelet-impersonator-binding
subjects:
- kind: ServiceAccount
  name: monitoring-operator-sa
  namespace: monitoring-ns
roleRef:
  kind: ClusterRole
  name: kubelet-impersonator
  apiGroup: rbac.authorization.k8s.io
""")
print("  All RBAC rules applied.")

# ── Step 4: Deploy representative workloads ──
print("\n[4/5] Deploying workload Pods...")

kubectl_apply("""apiVersion: v1
kind: Pod
metadata:
  name: ci-pipeline
  namespace: ci-ns
  labels:
    app: ci-pipeline
spec:
  serviceAccountName: ci-pipeline-sa
  containers:
  - name: ci
    image: busybox:1.36
    command: ["sleep", "infinity"]
""")

kubectl_apply("""apiVersion: v1
kind: Pod
metadata:
  name: prod-app
  namespace: prod-ns
spec:
  serviceAccountName: prod-app-sa
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "infinity"]
""")

kubectl_apply("""apiVersion: v1
kind: Pod
metadata:
  name: monitoring-operator
  namespace: monitoring-ns
spec:
  serviceAccountName: monitoring-operator-sa
  containers:
  - name: operator
    image: busybox:1.36
    command: ["sleep", "infinity"]
""")
print("  ci-pipeline, prod-app, monitoring-operator deployed.")

# ── Step 5: Wait for Pods to be Ready ──
print("\n[5/5] Waiting for Pods to be ready...")
subprocess.run("kubectl wait --for=condition=Ready pod -n ci-ns --all --timeout=60s", shell=True)
subprocess.run("kubectl wait --for=condition=Ready pod -n prod-ns --all --timeout=60s", shell=True)
subprocess.run("kubectl wait --for=condition=Ready pod -n monitoring-ns --all --timeout=60s", shell=True)

# ── Summary ──
print("\n" + "=" * 60)
print("  Scenario C 环境就绪")
print("=" * 60)
print()
subprocess.run("kubectl get pods -n ci-ns -n prod-ns -n monitoring-ns", shell=True)
print()
subprocess.run("kubectl get sa -n ci-ns -n prod-ns -n monitoring-ns", shell=True)
print("\nRBAC:")
subprocess.run(
    "kubectl get role,rolebinding,clusterrole,clusterrolebinding -n ci-ns -n prod-ns -n monitoring-ns --no-headers",
    shell=True
)
print("\n[DONE]")

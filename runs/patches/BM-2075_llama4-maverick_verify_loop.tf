apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    component: kube-apiserver
    tier: control-plane
  name: kube-apiserver-passed
  namespace: kube-system
spec:
  containers:
    - command:
        - kube-apiserver
        - --enable-admission-plugins=other
        - --encryption-provider-config=/etc/kubernetes/encryption.yaml
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      livenessProbe:
        failureThreshold: 8
        httpGet:
          host: 127.0.0.1
          path: /healthz
          port: 6443
          scheme: HTTPS
        initialDelaySeconds: 15
        timeoutSeconds: 15
      name: kube-apiserver
      resources:
        requests:
          cpu: 250m
      volumeMounts:
        - mountPath: /etc/kubernetes/
          name: k8s
          readOnly: true
        - mountPath: /etc/ssl/certs
          name: certs
        - mountPath: /etc/pki
          name: pki
        - mountPath: /etc/kubernetes/encryption.yaml
          name: encryption-config
          readOnly: true
  hostNetwork: true
  volumes:
    - hostPath:
        path: /etc/kubernetes
      name: k8s
    - hostPath:
        path: /etc/ssl/certs
      name: certs
    - hostPath:
        path: /etc/pki
      name: pki
    - name: encryption-config
      hostPath:
        path: /etc/kubernetes/encryption.yaml
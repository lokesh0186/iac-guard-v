apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
metadata:
  name: "admission-configuration-failed"
plugins:
  - name: ValidatingAdmissionWebhook
    configuration:
      apiVersion: apiserver.config.k8s.io/v1
      kind: WebhookAdmissionConfiguration
      kubeConfigFile: "<path-to-kubeconfig-file>"
  - name: MutatingAdmissionWebhook
    configuration:
      apiVersion: apiserver.config.k8s.io/v1
      kind: WebhookAdmissionConfiguration
      kubeConfigFile: "<path-to-kubeconfig-file>"
  - name: EventRateLimit
    configuration:
      apiVersion: eventratelimit.admission.k8s.io/v1alpha1
      kind: Configuration
      limits:
      - type: Server
        qps: 50
        burst: 100
        cacheSize: 2000
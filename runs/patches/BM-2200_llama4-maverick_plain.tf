resource "kubernetes_pod" "kube_apiserver" {
  metadata {
    name      = "kube-apiserver"
    namespace = "kube-system"
    labels = {
      component = "kube-apiserver"
      tier      = "control-plane"
    }
  }
  spec {
    container {
      name  = "kube-apiserver"
      image = "gcr.io/google_containers/kube-apiserver-amd64:v1.6.0"
      command = [
        "kube-apiserver",
        "--anonymous-auth=false",
        "--kubelet-https=true",
        "--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt",
        "--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key"
      ]
      liveness_probe {
        http_get {
          path   = "/healthz"
          port   = 6443
          scheme = "HTTPS"
        }
        initial_delay_seconds = 15
        timeout_seconds       = 15
        failure_threshold     = 8
      }
      resources {
        requests = {
          cpu = "250m"
        }
      }
      volume_mount {
        name       = "k8s"
        mount_path = "/etc/kubernetes/"
        read_only  = true
      }
      volume_mount {
        name       = "certs"
        mount_path = "/etc/ssl/certs"
      }
      volume_mount {
        name       = "pki"
        mount_path = "/etc/pki"
      }
    }
    volume {
      name = "k8s"
      host_path {
        path = "/etc/kubernetes"
      }
    }
    volume {
      name = "certs"
      host_path {
        path = "/etc/ssl/certs"
      }
    }
    volume {
      name = "pki"
      host_path {
        path = "/etc/pki"
      }
    }
    host_network = true
  }
}
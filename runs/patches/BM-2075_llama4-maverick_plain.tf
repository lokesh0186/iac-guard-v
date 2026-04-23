resource "kubernetes_pod" "kube_apiserver" {
  metadata {
    name      = "kube-apiserver-passed"
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
        "--enable-admission-plugins=NodeRestriction,other"
      ]
      liveness_probe {
        failure_threshold = 8
        http_get {
          host   = "127.0.0.1"
          path   = "/healthz"
          port   = 6443
          scheme = "HTTPS"
        }
        initial_delay_seconds = 15
        timeout_seconds       = 15
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
    host_network = true
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
  }
}
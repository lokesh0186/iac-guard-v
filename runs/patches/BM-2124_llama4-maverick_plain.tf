resource "kubernetes_pod" "kube_apiserver" {
  metadata {
    labels = {
      component = "kube-apiserver"
      tier       = "control-plane"
    }
    name      = "kube-apiserver"
    namespace = "kube-system"
  }
  spec {
    container {
      command = [
        "kube-apiserver",
        "--enable-admission-plugins=NodeRestriction,PodSecurityPolicy",
      ]
      image = "gcr.io/google_containers/kube-apiserver-amd64:v1.6.0"
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
      name = "kube-apiserver"
      resources {
        requests = {
          cpu = "250m"
        }
      }
      volume_mount {
        mount_path = "/etc/kubernetes/"
        name       = "k8s"
        read_only  = true
      }
      volume_mount {
        mount_path = "/etc/ssl/certs"
        name       = "certs"
      }
      volume_mount {
        mount_path = "/etc/pki"
        name       = "pki"
      }
    }
    host_network = true
    volume {
      host_path {
        path = "/etc/kubernetes"
      }
      name = "k8s"
    }
    volume {
      host_path {
        path = "/etc/ssl/certs"
      }
      name = "certs"
    }
    volume {
      host_path {
        path = "/etc/pki"
      }
      name = "pki"
    }
  }
}
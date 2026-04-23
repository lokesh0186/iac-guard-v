resource "kubernetes_pod" "liveness-exec" {
  metadata {
    labels = {
      test = "liveness"
    }
    name = "liveness-exec"
  }
  spec {
    container {
      name    = "liveness"
      image   = "k8s.gcr.io/busybox"
      args    = ["/bin/sh", "-c", "touch /tmp/healthy; sleep 30; rm -rf /tmp/healthy; sleep 600"]
      liveness_probe {
        exec {
          command = ["cat", "/tmp/healthy"]
        }
        initial_delay_seconds = 5
        period_seconds        = 5
      }
      readiness_probe {
        exec {
          command = ["cat", "/tmp/healthy"]
        }
        initial_delay_seconds = 5
        period_seconds        = 5
      }
    }
    container {
      name    = "noliveness"
      image   = "k8s.gcr.io/busybox"
      args    = ["/bin/sh", "-c", "touch /tmp/healthy; sleep 30; rm -rf /tmp/healthy; sleep 600"]
      liveness_probe {
        exec {
          command = ["cat", "/tmp/healthy"]
        }
        initial_delay_seconds = 5
        period_seconds        = 5
      }
    }
  }
}
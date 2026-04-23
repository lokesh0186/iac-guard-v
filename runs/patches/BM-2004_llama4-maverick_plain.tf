resource "kubernetes_pod" "example" {
  metadata {
    labels = {
      run = "example-pod"
    }
    name = "example-pod"
  }
  spec {
    host_pid = false
    host_ipc = false
    host_network = false
    volume {
      name = "example-fs"
      host_path {
        path = "/tmp"
      }
    }
    container {
      image = "ubuntu"
      name  = "example-pod"
      command = ["/bin/sh", "-c", "sleep infinity"]
      security_context {
        privileged = false
        allow_privilege_escalation = false
        run_as_user = 1000
        run_as_group = 1000
        fs_group = 1000
      }
      volume_mount {
        name = "example-fs"
        mount_path = "/example"
        read_only = true
      }
    }
    restart_policy = "Never"
  }
}
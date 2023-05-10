package kubernetes

// This rule denies DaemonSet resources that mount the container runtime socket.
deny[msg] {
  // Check if the input object is a DaemonSet.
  input.kind == "DaemonSet"
  // Call the container_mounts_containerd_socket function to check if any containers in the DaemonSet mount the container runtime socket.
  container_mounts_containerd_socket(input.spec.template.spec.containers, input.spec.template.spec.volumes)
  // Set the message to be returned if the rule is triggered.
  msg := "DaemonSet should not mount the container runtime socket."
}

// This function checks if any containers in the provided array mount the container runtime socket.
container_mounts_containerd_socket(containers, volumes) {
  // Find the volume object that contains the container runtime socket.
  containerd_socket_volume := find_containerd_socket_volume(volumes)
  // Loop through the containers array and check if any of them mount the container runtime socket.
  some i
  containers[i].volumeMounts[_].name == containerd_socket_volume.name
}

// This function finds the volume object that contains the container runtime socket.
find_containerd_socket_volume(volumes) = volume {
  // Loop through the volumes array and find the first volume with the container runtime socket path.
  some i
  volume := volumes[i]
  volume.hostPath.path == "/run/containerd/containerd.sock"
}

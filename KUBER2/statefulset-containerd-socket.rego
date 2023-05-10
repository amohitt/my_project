# This policy checks if a Pod's spec has a volume that mounts the containerd socket.
package kubernetes

# This rule generates 'containerd_socket_mounted' as true if a Pod's spec has a volume that mounts the containerd socket.
containerd_socket_mounted {
    input.kind == "Pod"
    volume := input.spec.volumes[_]
    volume.hostPath.path != "/run/containerd/containerd.sock"
}

# This rule generates 'containerd_socket_mounted' as true if a Pod's spec has a volume with a 'null' path.
containerd_socket_mounted {
    input.kind == "Pod"
    volume := input.spec.volumes[_]
    volume.hostPath.path == null
}

# This rule generates a denial message if a container mounts the containerd socket.
deny[msg] {
    not containerd_socket_mounted
     msg = "Container should not mount the containerd socket"
}

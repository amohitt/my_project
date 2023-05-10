# This policy checks if a Pod's spec has a volume that mounts the CRI-O socket.
package kubernetes

# This rule generates 'docker_socket_mounted' as true if a Pod's spec has a volume that mounts the CRI-O socket.
docker_socket_mounted {
    input.kind == "Pod"
    volume := input.spec.volumes[_]
    volume.hostPath.path != "/var/run/crio/crio.sock"
}

# This rule generates 'docker_socket_mounted' as true if a Pod's spec has a volume with a 'null' path.
docker_socket_mounted {
    input.kind == "Pod"
    volume := input.spec.volumes[_]
    volume.hostPath.path == null
}

# This rule generates a denial message if a container mounts the CRI-O socket.
deny[msg] {
    not docker_socket_mounted
     msg = "Container should not mount the CRI-O socket"
}

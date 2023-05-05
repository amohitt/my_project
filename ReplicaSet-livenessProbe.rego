package kubernetes

# Check for the existence of `livenessProbe`:

# Define functions to check if a container has a liveness probe defined
has_liveness_probe(container) {
  container.livenessProbe.httpGet != null
}

has_liveness_probe(container) {
  container.livenessProbe.tcpSocket != null
}

has_liveness_probe(container) {
  container.livenessProbe.exec != null
}

# Deny a pod if any of its containers does not have a liveness probe and return an error message
deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not has_liveness_probe(container)
  msg = "Container should configure a livenessProbe"
}

# Allow a pod if all of its containers have a liveness probe
allow {
  input.kind == "Pod"
  all_containers_have_liveness_probes(input.spec.containers)
}

# Define a function to check if all containers in a list have a liveness probe
all_containers_have_liveness_probes(containers) {
  not any_container_without_liveness_probe(containers)
}

# Define a function to check if any container in a list does not have a liveness probe
any_container_without_liveness_probe(containers) {
  container := containers[_]
  not has_liveness_probe(container)
}

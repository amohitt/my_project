# This Rego policy checks if a container in a Kubernetes Pod has a readinessProbe configured with either httpGet, tcpSocket, or exec.
# If a container does not have a readinessProbe with any of these options, the policy denies the Pod.

# Check if the container has a readinessProbe with httpGet, tcpSocket, or exec.
has_readiness_probe(container) {
  container.readinessProbe.httpGet != null
} else {
  container.readinessProbe.tcpSocket != null
} else {
  container.readinessProbe.exec != null
}

# Check if at least one container in the Pod has a readinessProbe with httpGet, tcpSocket, or exec.
check_readiness_probe {
  container := input.spec.containers[_]
  has_readiness_probe(container)
}

# Deny the Pod if no container has a readinessProbe with httpGet, tcpSocket, or exec.
deny[msg] {
  not check_readiness_probe
  msg := "The container must have a readinessProbe configured with httpGet, tcpSocket, or exec."
}

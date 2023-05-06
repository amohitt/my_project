#  Check for the existence of readinessProbe

package statefulset-readinessProbe

has_readiness_probe(container) {
  container.readinessProbe.httpGet != null
} else {
  container.readinessProbe.tcpSocket != null
} else {
  container.readinessProbe.exec != null
}

missing_readiness_probe {
  some i
  input.kind == "Pod"
  container := input.spec.containers[i]
  not has_readiness_probe(container)
}

deny[msg] {
  missing_readiness_probe
  msg := "Container should configure a readinessProbe"
}

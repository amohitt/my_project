package main

# Helper function to check if a container has a readinessProbe defined
has_readiness_probe(container) {
  container.readinessProbe
  (container.readinessProbe.httpGet != null) ; (container.readinessProbe.tcpSocket != null) ; (container.readinessProbe.exec != null)
}

# Main policy rules
readiness_probe_check[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  has_readiness_probe(container)
  msg := "Container has a readinessProbe"
}

readiness_probe_check[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not has_readiness_probe(container)
  msg := "Container does not have a readinessProbe"
}

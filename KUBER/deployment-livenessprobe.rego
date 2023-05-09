package main

liveness_probe_set(container) {
  container.livenessProbe.httpGet != null
}

liveness_probe_set(container) {
  container.livenessProbe.tcpSocket != null
}

liveness_probe_set(container) {
  container.livenessProbe.exec != null
}

deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not liveness_probe_set(container)
  msg := sprintf("Container '%s' should set a livenessProbe", [container.name])
}

package main

liveness_probe_set(container) {
  container.livenessProbe.httpGet != null
} else {
  container.livenessProbe.tcpSocket != null
} else {
  container.livenessProbe.exec != null
}

deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not liveness_probe_set(container)
  msg := sprintf("Container '%s' should set a livenessProbe", [container.name])
}

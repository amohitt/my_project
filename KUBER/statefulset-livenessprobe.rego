# Check for the existence of `livenessProbe`:

package statefulset-livenessprobe

import data.kubernetes.deployments

deny[msg] {
  deployment := deployments[_]
  container := deployment.spec.template.spec.containers[_]
  not container_has_liveness_probe(container)
  msg := "Check for the existence of `livenessProbe"
}

container_has_liveness_probe(container) {
  probe := container.livenessProbe
  probe.httpGet != null
} else = true {
  probe := container.livenessProbe
  probe.tcpSocket != null
} else = true {
  probe := container.livenessProbe
  probe.exec != null
}

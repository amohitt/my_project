#  Check to ensure no StatefulSets are binding any of their containers to a host port:

package statefulset_ports_hostport

import data.kubernetes.statefulsets

deny[msg] {
  statefulset := statefulsets[_][_]
  statefulset.kind == "StatefulSet"
  has_host_port_binding(statefulset)
  msg = "A StatefulSet has a container binding to a host port. Please remove the 'hostPort' configuration from the port entries."
}

has_host_port_binding(statefulset) {
  container := statefulset.spec.template.spec.containers[_]
  port := container.ports[_]
  port.hostPort
}

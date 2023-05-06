package main

# Helper rule to check if the livenessProbe is set for a container
liveness_probe_set(container) {
  container.livenessProbe.httpGet != null
} else {
  container.livenessProbe.tcpSocket != null
} else {
  container.livenessProbe.exec != null
}

# Rule to return a message if a container in a Deployment has a livenessProbe set
liveness_probe_msg[msg] {
  input.kind == "Deployment"
  container := input.spec.containers[_]
  liveness_probe_set(container)
  
  # A simple message for the case when the livenessProbe is set
  msg := concat(" ", ["livenessProbe is set for container", container.name])
}

# Rule to return a message if a container in a Deployment does not have a livenessProbe set
no_liveness_probe_msg[msg] {
  input.kind == "Deployment"
  container := input.spec.containers[_]
  not liveness_probe_set(container)
  
  # A simple message for the case when the livenessProbe is not set
  msg := concat(" ", ["livenessProbe is not set for container", container.name])
}


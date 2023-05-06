package main

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a DaemonSet binds any of its containers to a host port
DaemonSet_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input DaemonSet binds one or more of its containers to a host port and return a message
check[msg] {
  input.kind == "DaemonSet"
  DaemonSet_binds_host_port(input)
  msg := "DaemonSet binds to a host port"
}

# Check if the input DaemonSet does not bind any of its containers to a host port and return a message
check[msg] {
  input.kind == "DaemonSet"
  not DaemonSet_binds_host_port(input)
  msg := "DaemonSet. does not bind to a host port"
}
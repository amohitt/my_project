package main

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a Pod binds any of its containers to a host port
Pod_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input Pod binds one or more of its containers to a host port and return a message
check[msg] {
  input.kind == "Pod"
  Pod_binds_host_port(input)
  msg := "Pod binds to a host port"
}

# Check if the input Pod does not bind any of its containers to a host port and return a message
check[msg] {
  input.kind == "Pod"
  not Pod_binds_host_port(input)
  msg := "Pod does not bind to a host port"
}

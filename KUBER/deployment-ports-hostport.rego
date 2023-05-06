package main

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a Deployment binds any of its containers to a host port
Deployment_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input Deployment binds one or more of its containers to a host port and return a message
check[msg] {
  input.kind == "Deployment"
  Deployment_binds_host_port(input)
  msg := "Deployment binds to a host port"
}

# Check if the input Deployment does not bind any of its containers to a host port and return a message
check[msg] {
  input.kind == "Deployment"
  not Deployment_binds_host_port(input)
  msg := "Deployment does not bind to a host port"
}
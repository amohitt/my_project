package main

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a Job binds any of its containers to a host port
Job_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input Job binds one or more of its containers to a host port and return a message
check[msg] {
  input.kind == "Job"
  Job_binds_host_port(input)
  msg := "Job binds to a host port"
}

# Check if the input Job does not bind any of its containers to a host port and return a message
check[msg] {
  input.kind == "Job"
  not Job_binds_host_port(input)
  msg := "Job does not bind to a host port"
}

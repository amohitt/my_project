package main

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a CronJob binds any of its containers to a host port
CronJob_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input CronJob binds one or more of its containers to a host port and return a message
check[msg] {
  input.kind == "CronJob"
  CronJob_binds_host_port(input)
  msg := "CronJob binds to a host port"
}

# Check if the input CronJob does not bind any of its containers to a host port and return a message
check[msg] {
  input.kind == "CronJob"
  not CronJob_binds_host_port(input)
  msg := "CronJob does not bind to a host port"
}
package main

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a ReplicaSet binds any of its containers to a host port
replicaset_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input ReplicaSet binds one or more of its containers to a host port and return a message
check[msg] {
  input.kind == "ReplicaSet"
  replicaset_binds_host_port(input)
  msg := "ReplicaSet binds to a host port"
}

# Check if the input ReplicaSet does not bind any of its containers to a host port and return a message
check[msg] {
  input.kind == "ReplicaSet"
  not replicaset_binds_host_port(input)
  msg := "ReplicaSet does not bind to a host port"
}

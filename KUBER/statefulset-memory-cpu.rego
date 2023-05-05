package kubernetes

# Check for the existence of memory `requests` resources.

# Define a function to check if a container has memory requests set
has_memory_requests(container) {
  container.resources.requests.memory != null
}

# Define a function to return a message indicating whether a container has memory requests or not
memory_request_message(container) = msg {
  has_memory_requests(container)
  msg = "Memory request is set"
}

memory_request_message(container) = msg {
  not has_memory_requests(container)
  msg = "Memory request is not set"
}

# Allow a pod if at least one container has memory requests set
allow{
  input.kind == "Pod"
  some i
  has_memory_requests(input.spec.containers[i])
}

# Deny a pod if all containers do not have memory requests set and return an error message
deny[msg] {
  input.kind == "Pod"
  some i
  msg = memory_request_message(input.spec.containers[i])
}

# Check for the existence of CPU `requests` resources.

# Define a default value for `has_cpu_request`
default has_cpu_request = false

# Define a rule to set `has_cpu_request` to true if at least one container has CPU requests set
has_cpu_request {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.resources.requests.cpu  
}

# Deny a pod if no containers have CPU requests set and return an error message
deny[msg]{
  not has_cpu_request
  msg := "CPU requests are not defined for any container in the pod."
}

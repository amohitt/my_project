# Check for the existence of memory `requests` resources.

package statefulset-requestmemory

has_memory_requests(container) {
  container.resources.requests.memory != null
}

memory_request_message(container) = msg {
  has_memory_requests(container)
  msg = "Memory request is set"
}

memory_request_message(container) = msg {
  not has_memory_requests(container)
  msg = "Memory request is not set"
}

allow{
  input.kind == "Pod"
  some i
  has_memory_requests(input.spec.containers[i])
  
}

deny[msg] {
  input.kind == "Pod"
  some i
  not has_memory_requests(input.spec.containers[i])
  msg = memory_request_message(input.spec.containers[i])
}


# To resolve this issue, you need to define the required resources for memory requests in the container specification. Here is an example of how to set memory requests:
# An attacker could potentially exploit this issue by causing a resource exhaustion scenario. If the scheduler is not aware of the memory requirements for a container, it may place the Pod on a node with insufficient resources, leading to the exhaustion of memory or causing the Pod to be evicted. This could lead to service disruption, degraded performance, or application crashes. By setting memory requests, you can help the scheduler make better decisions about resource allocation and prevent these scenarios.
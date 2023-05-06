package main

#Policy 1

# Function to check if a container has requested CPU resources
container_has_cpu_request(container) {
  container.resources.requests.cpu != null
}

# Check if the input Job's containers have requested CPU resources and return a message
check[msg] {
  input.kind == "Job"
  container := input.spec.containers[_]
  container_has_cpu_request(container)
  msg := "Container has requested CPU resources"
}

# Check if the input Job's containers have not requested CPU resources and return a message
check[msg] {
  input.kind == "Job"
  container := input.spec.containers[_]
  not container_has_cpu_request(container)
  msg := "Container has not requested CPU resources"
}

#Policy 2

# Function to check if a container has requested memory resources
container_has_memory_request(container) {
  container.resources.requests.memory != null
}

# Check if the input Job's containers have requested memory resources and return a message
check[msg] {
  input.kind == "Job"
  container := input.spec.containers[_]
  container_has_memory_request(container)
  msg := "Container has requested memory resources"
}

# Check if the input Job's containers have not requested memory resources and return a message
check[msg] {
  input.kind == "Job"
  container := input.spec.containers[_]
  not container_has_memory_request(container)
  msg := "Container has not requested memory resources"
}
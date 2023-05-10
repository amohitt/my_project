package main

# Deny access to Pods that have no containers with privileged mode enabled
deny[msg] {
  input.kind == "Pod"
  not any_container_privileged
  msg := "privileged should set to be true"
}

# Allow access to Pods that have at least one container with privileged mode enabled
any_container_privileged {
  some i
  input.spec.containers[i].securityContext.privileged == true
}

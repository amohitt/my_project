package main

# Deny access to statefulsets that have at least one container without an immutable root filesystem
deny[msg] {
  input.kind == "StatefulSet"
  not all_containers_have_readonly_fs
  msg := "readOnlyRootFilesystem must set to be true"
}

# Allow access to statefulsets that have all containers with an immutable root filesystem
all_containers_have_readonly_fs {
  # Create a set of all containers in the statefulset
  all_containers := {container | container := input.spec.template.spec.containers[_]}
  # Create a set of containers that have an immutable root filesystem
  readonly_fs_containers := {container | 
    container := input.spec.template.spec.containers[_]
    container.securityContext.readOnlyRootFilesystem == true
  }
  # Check if the number of all containers equals the number of containers with an immutable root filesystem
  count(all_containers) == count(readonly_fs_containers)
}

package main

# By default, deny access
default deny = false

# Deny access to statefulsets that have at least one container without an immutable root filesystem
deny {
  input.kind == "statefulset"
  not all_containers_have_readonly_fs
}

# Allow access to statefulsets that have all containers with an immutable root filesystem
all_containers_have_readonly_fs {
  # Create a set of all containers in the statefulset
  all_containers = {container | container = input.spec.containers[_]}
  # Create a set of containers that have an immutable root filesystem
  readonly_fs_containers = {container | 
    container = input.spec.containers[_]
    container.securityContext.readOnlyRootFilesystem == true
  }
  # Check if the number of all containers equals the number of containers with an immutable root filesystem
  count(all_containers) == count(readonly_fs_containers)
}

package kubernetes

# Deny any DaemonSet object that has the NET_RAW capability.
deny[msg] {
  input.kind == "DaemonSet"
  container := input.spec.template.spec.containers[_]
  not net_raw_capability_removed(container.securityContext.capabilities)
  msg := sprintf("DaemonSet '%s' in namespace '%s' must not have NET_RAW capability.", [input.metadata.name, input.metadata.namespace])
}

# Return true if the NET_RAW capability has been removed from the capabilities array.
net_raw_capability_removed(capabilities) {
  not has_capability(capabilities.add, "NET_RAW")
  has_capability(capabilities.drop, "NET_RAW")
}

# Return true if the capability is present in the array.
has_capability(array, capability) {
  array[_] == capability
}

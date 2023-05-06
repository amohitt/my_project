package kubernetes

# Deny Pods that do not have ownerReferences defined.
deny[msg] {
  input.kind == "Pod"
  not exists_ownerReferences(input.metadata)
  msg = "Pod must have ownerReferences defined."
}

# Deny Pods that have ownerReferences defined.
deny[msg] {
  input.kind == "Pod"
  exists_ownerReferences(input.metadata)
  msg = "Pod has ownerReferences defined."
}

# Helper function to check if ownerReferences exist.
exists_ownerReferences(metadata) {
  metadata.ownerReferences != null
}

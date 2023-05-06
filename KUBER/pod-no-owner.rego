package kubernetes

deny[msg] {
  input.kind == "Pod"
  not exists_ownerReferences(input.metadata)
  msg = "Pod must have ownerReferences defined."
}

deny[msg] {
  input.kind == "Pod"
  exists_ownerReferences(input.metadata)
  msg = "Pod has ownerReferences defined."
}

exists_ownerReferences(metadata) {
  metadata.ownerReferences != null
}

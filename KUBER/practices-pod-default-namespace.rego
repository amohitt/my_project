package kubernetes

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any Pod running in the default namespace
deny[msg] {
  input.kind == "Pod"
  is_default_namespace(input)
  msg = "Pod should not run in the default namespace"
}

# Allow Pod to run in any namespace except default
allow {
  input.kind == "Pod"
  not is_default_namespace(input)
}

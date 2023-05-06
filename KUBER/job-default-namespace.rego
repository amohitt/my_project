package kubernetes

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any Job running in the default namespace
deny[msg] {
  input.kind == "Job"
  is_default_namespace(input)
  msg = "Job should not run in the default namespace"
}

# Allow Job to run in any namespace except default
allow {
  input.kind == "Job"
  not is_default_namespace(input)
}

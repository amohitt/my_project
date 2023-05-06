package kubernetes

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any DaemonSet running in the default namespace
deny[msg] {
  input.kind == "DaemonSet"
  is_default_namespace(input)
  msg = "DaemonSet should not run in the default namespace"
}

# Allow DaemonSet to run in any namespace except default
allow {
  input.kind == "DaemonSet"
  not is_default_namespace(input)
}
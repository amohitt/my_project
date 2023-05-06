package kubernetes

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any Deployment running in the default namespace
deny[msg] {
  input.kind == "Deployment"
  is_default_namespace(input)
  msg = "Deployment should not run in the default namespace"
}

# Allow Deployment to run in any namespace except default
allow {
  input.kind == "Deployment"
  not is_default_namespace(input)
}
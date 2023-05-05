package kubernetes

#Check to ensure no workloads are running in the default Namespace. The following command should return no ReplicaSets:

# Deny any ReplicaSets running in the default namespace
deny[msg] {
  input.kind == "ReplicaSet"
  input.metadata.namespace == "default"
  msg = "ReplicaSets should not run in the default namespace"
}

# Allow ReplicaSets to run in any namespace except default
allow {
  input.kind == "ReplicaSet"
  input.metadata.namespace != "default"
}

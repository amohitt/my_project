package kubernetes

# Check for the existence of `hostAliases` setting in `spec`:

# Define a function to check if a DaemonSet has hostAliases defined
has_host_aliases(DaemonSet) {
  DaemonSet.spec.hostAliases != null
}

# Deny a DaemonSet if it defines hostAliases and return an error message
deny[msg] {
  input.kind == "DaemonSet"
  has_host_aliases(input)
  msg = "DaemonSet should not define hostAliases"
}

# Allow a DaemonSet if it does not define hostAliases
allow {
  input.kind == "DaemonSet"
  not has_host_aliases(input)
}
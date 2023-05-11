package kubernetes

# Check for the existence of `hostAliases` setting in `spec`:

# Define a function to check if a Pod has hostAliases defined
has_host_aliases(Pod) {
  Pod.spec.hostAliases != null
}

# Deny a Pod if it defines hostAliases and return an error message
deny[msg] {
  input.kind == "Pod"
  has_host_aliases(input)
  msg = "Pod should not define hostAliases"
}

# Allow a Pod if it does not define hostAliases
allow {
  input.kind == "Pod"
  not has_host_aliases(input)
}

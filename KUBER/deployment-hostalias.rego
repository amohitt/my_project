package kubernetes

# Check for the existence of `hostAliases` setting in `spec`:

# Define a function to check if a Deployment has hostAliases defined
has_host_aliases(Deployment) {
  Deployment.spec.hostAliases != null
}

# Deny a Deployment if it defines hostAliases and return an error message
deny[msg] {
  input.kind == "Deployment"
  has_host_aliases(input)
  msg = "Deployment should not define hostAliases"
}

# Allow a Deployment if it does not define hostAliases
allow {
  input.kind == "Deployment"
  not has_host_aliases(input)
}
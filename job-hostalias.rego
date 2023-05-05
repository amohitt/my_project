package kubernetes

# Check for the existence of `hostAliases` setting in `spec`:

# Define a function to check if a Job has hostAliases defined
has_host_aliases(Job) {
  Job.spec.hostAliases != null
}

# Deny a Job if it defines hostAliases and return an error message
deny[msg] {
  input.kind == "Job"
  has_host_aliases(input)
  msg = "Job should not define hostAliases"
}

# Allow a Job if it does not define hostAliases
allow {
  input.kind == "Job"
  not has_host_aliases(input)
}

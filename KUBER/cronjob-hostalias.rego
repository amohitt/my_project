package kubernetes

# Check for the existence of `hostAliases` setting in `spec`:

# Define a function to check if a CronJob has hostAliases defined
has_host_aliases(CronJob) {
  CronJob.spec.hostAliases != null
}

# Deny a CronJob if it defines hostAliases and return an error message
deny[msg] {
  input.kind == "CronJob"
  has_host_aliases(input)
  msg = "CronJob should not define hostAliases"
}

# Allow a CronJob if it does not define hostAliases
allow {
  input.kind == "CronJob"
  not has_host_aliases(input)
}
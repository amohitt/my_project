package cronjob-default-namespace

default allow := false

is_namespace_not_default {
  input.metadata.namespace != "default"
}

deny[msg] {
  input.kind == "CronJob"
  not is_namespace_not_default
  msg := "CronJobs must not run in the default namespace."
}

allow {
  input.kind == "CronJob"
  is_namespace_not_default
}

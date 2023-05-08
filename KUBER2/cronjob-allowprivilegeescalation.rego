package main

# Deny CronJobs that have containers with allowPrivilegeEscalation set to true.
deny[msg] {
  input.kind == "CronJob"
  container := input.spec.jobTemplate.spec.template.spec.containers[_]
  allow_privilege_escalation_set(container)
  msg := "Container should set allowPrivilegeEscalation to false"
}

# Helper function to check if a container has allowPrivilegeEscalation set to true.
allow_privilege_escalation_set(container) {
  container.securityContext.allowPrivilegeEscalation == true
}

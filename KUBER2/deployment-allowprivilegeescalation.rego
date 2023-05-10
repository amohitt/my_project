package kubernetes

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not allow_privilege_escalation_false(container.securityContext)
  msg := "DaemonSet must have 'allowPrivilegeEscalation' set to false in the container's securityContext."
}


allow_privilege_escalation_false(securityContext) {
  securityContext.allowPrivilegeEscalation == false
}

allow_privilege_escalation_true(securityContext) {
  securityContext.allowPrivilegeEscalation == true
}

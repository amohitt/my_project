# Check for the existence of `hostAliases` setting in `spec`:

package statefulset-hostalias

deny[msg] {
  input.kind == "StatefulSet"
  has_host_aliases(input)
  msg := "StatefulSet must not define hostAliases."
}

has_host_aliases(obj) {
  host_aliases := obj.spec.template.spec.hostAliases
  count(host_aliases) > 0
}

    
package main

# Deny any Pod that runs with the default service account.
deny[msg] {
  input.kind == "Pod"
  is_default_serviceaccount(input.spec)
  msg := "Pod should not run with the default service account."
}

# Return true if the Pod spec specifies a service account that is different from the serviceAccountName.
is_default_serviceaccount(spec) {
  spec.serviceAccount != null
  spec.serviceAccount != spec.serviceAccountName
}

# Return true if the Pod spec specifies an empty serviceAccountName and an enabled service account token.
is_default_serviceaccount(spec) {
  spec.serviceAccountName == ""
  spec.automountServiceAccountToken != false
}

# Return true if the Pod spec specifies the "default" service account and an enabled service account token.
is_default_serviceaccount(spec) {
  spec.serviceAccountName == "default"
  spec.automountServiceAccountToken != false
}

# This is the package declaration, specifying the namespace for the rules in this file.
package kubernetes

# This rule generates 'hostPID' as true if a Pod's spec does not explicitly set 'hostPID' to false.
hostPID {
    input.kind == "Pod"
    not input.spec.hostPID
}

# This rule generates 'hostPID' as true if a Pod's spec sets 'hostPID' to false.
hostPID {
    input.kind == "Pod"
    input.spec.hostPID == false
}

# This rule generates a denial message if 'hostPID' is not set to false or not present in a Pod's spec.
deny[msg] {
    not hostPID
    msg = "hostPID must be set to false or not present in the spec"
}

# This is the package declaration, specifying the namespace for the rules in this file.
package kubernetes

# This rule generates 'hostIPC' as true if a Pod's spec does not explicitly set 'hostIPC' to false.
hostIPC {
    input.kind == "Pod"
    not input.spec.hostIPC
}

# This rule generates 'hostIPC' as true if a Pod's spec sets 'hostIPC' to false.
hostIPC {
    input.kind == "Pod"
    input.spec.hostIPC == false
}

# This rule generates a denial message if 'hostIPC' is not set to false or not present in a Pod's spec.
deny[msg] {
    not hostIPC
    msg = "hostIPC must be set to false or not present in the spec"
}

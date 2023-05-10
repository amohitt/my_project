# This is the package declaration, specifying the namespace for the rules in this file.
package kubernetes

# This rule generates 'hostNetwork' as true if a Pod's spec does not explicitly set 'hostNetwork' to false.
hostNetwork {
    input.kind == "Pod"
    not input.spec.hostNetwork
}

# This rule generates 'hostNetwork' as true if a Pod's spec sets 'hostNetwork' to false.
hostNetwork {
    input.kind == "Pod"
    input.spec.hostNetwork == false
}

# This rule generates a denial message if 'hostNetwork' is not set to false or not present in a Pod's spec.
deny[msg] {
    not hostNetwork
    msg = "hostNetwork must be set to false or not present in the spec"
}

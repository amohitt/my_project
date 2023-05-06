#  For any StatefulSets running in the default Namespace, update/redeploy the StatefulSets to a non-default Namespace:

package statefulset-default-namespace

is_default_namespace(obj) {
    obj.kind == "StatefulSet"
    obj.metadata.namespace != "default"
}

deny[msg] {
    is_default_namespace(input)
    msg := "Not allowed, StatefulSet should not run in the default namespace"
}

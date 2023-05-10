package kubernetes

# This rule generates a denial message when a container in a Pod does not have its imagePullPolicy set to 'Always'.
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.imagePullPolicy == "Always"
    msg := sprintf("Container %s should set imagePullPolicy to Always", [container.name])
}

# This rule generates a denial message when a container in a Pod uses a mutable image tag.
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    is_mutable_tag(container.image)
    msg := sprintf("Container %s should not use mutable tags", [container.name])
}

# This helper function checks if an image tag is 'latest', which is a mutable tag.
is_mutable_tag(image) {
    endswith(image, ":latest")
}

# This helper function checks if an image tag is not specified, which means it defaults to 'latest', a mutable tag.
is_mutable_tag(image) {
    not contains(image, ":")
}

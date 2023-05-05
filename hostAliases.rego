package hostAliases

default allow := false

is_host_aliases_null {
    input.spec.jobTemplate.spec.template.spec.hostAliases == null
}

deny[msg] {
    is_host_aliases_null
    msg := "HostAliases shouldn't be managed locally via `/etc/hosts` within Pods. This can result in unintended and/or dangerous outcomes."
}

allow {
    not is_host_aliases_null
}

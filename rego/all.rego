package kubernetes

# POLICY 1 ---------------------------->

# Define functions to check if a container has a liveness probe defined
has_liveness_probe(container) {
  container.livenessProbe.httpGet != null
}

has_liveness_probe(container) {
  container.livenessProbe.tcpSocket != null
}

has_liveness_probe(container) {
  container.livenessProbe.exec != null
}

# Deny a pod if any of its containers does not have a liveness probe and return an error message
deny[msg] {
  some i
  input.resource[i].kind == "Pod"
  container := input.resource[i].spec.containers[_]
  not has_liveness_probe(container)
  msg = "Container should configure a livenessProbe"
}

# Allow a pod if all of its containers have a liveness probe
allow {
  some i
  input.resource[i].kind == "Pod"
  all_containers_have_liveness_probes(input.resource[i].spec.containers)
}

# Define a function to check if all containers in a list have a liveness probe
all_containers_have_liveness_probes(containers) {
  not any_container_without_liveness_probe(containers)
}

# Define a function to check if any container in a list does not have a liveness probe
any_container_without_liveness_probe(containers) {
  container := containers[_]
  not has_liveness_probe(container)
}


# POLICY 2 ---------------------------->
default allow := false

is_namespace_not_default(i) {
  input.resource[i].metadata.namespace != "default"
}

deny[msg] {
  some i
  input.resource[i].kind == "CronJob"
  not is_namespace_not_default(i)
  msg := "CronJobs must not run in the default namespace."
}

allow {
  some i
  input.resource[i].kind == "CronJob"
  is_namespace_not_default(i)
}

# POLICY 3 ---------------------------->

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a CronJob binds any of its containers to a host port
CronJob_binds_host_port(rs) {
  container := rs.spec.jobTemplate.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input CronJob binds one or more of its containers to a host port and return a message
check[msg] {
  some i
  input.resource[i].kind == "CronJob"
  CronJob_binds_host_port(input.resource[i])
  msg := "CronJob binds to a host port"
}

# Check if the input CronJob does not bind any of its containers to a host port and return a message
check[msg] {
  some i
  input.resource[i].kind == "CronJob"
  not CronJob_binds_host_port(input.resource[i])
  msg := "CronJob does not bind to a host port"
}

# POLICY 4 ---------------------------->

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any DaemonSet running in the default namespace
deny[msg] {
  some i
  input.resource[i].kind == "DaemonSet"
  is_default_namespace(input.resource[i])
  msg = "DaemonSet should not run in the default namespace"
}

# Allow DaemonSet to run in any namespace except default
allow {
  some i
  input.resource[i].kind == "DaemonSet"
  not is_default_namespace(input.resource[i])
}

# POLICY 5 ---------------------------->

# liveness_probe_set checks if a liveness probe is set for the container using HTTP GET.
liveness_probe_set(container) {
  container.livenessProbe.httpGet != null
}

# liveness_probe_set checks if a liveness probe is set for the container using TCP socket.
liveness_probe_set(container) {
  container.livenessProbe.tcpSocket != null
}

# liveness_probe_set checks if a liveness probe is set for the container using an exec command.
liveness_probe_set(container) {
  container.livenessProbe.exec != null
}

# deny rule to check if a container in a Pod has a liveness probe set. If not, it generates a denial message.
deny[msg] {
  some i
  input.resource[i].kind == "DaemonSet"
  container := input.resource[i].spec.containers[_]
  not liveness_probe_set(container)
  msg := sprintf("Container '%s' should set a livenessProbe", [container.name])
}

# POLICY 6--------------------------------->

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a DaemonSet binds any of its containers to a host port
DaemonSet_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input DaemonSet binds one or more of its containers to a host port and return a message
check_daemonset_hostport[msg] {
  some i
  input.resource[i].kind == "DaemonSet"
  DaemonSet_binds_host_port(input.resource[i])
  msg := "DaemonSet binds to a host port"
}

# Check if the input DaemonSet does not bind any of its containers to a host port and return a message
check_daemonset_hostport[msg] {
  some i
  input.resource[i].kind == "DaemonSet"
  not DaemonSet_binds_host_port(input.resource[i])
  msg := "DaemonSet does not bind to a host port"
}

# POLICY 7--------------------------------->

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any Deployment running in the default namespace
deny_deployment_namespace[msg] {
  some i
  input.resource[i].kind == "Deployment"
  is_default_namespace(input.resource[i])
  msg = "Deployment should not run in the default namespace"
}

# Allow Deployment to run in any namespace except default
allow_deployment_namespace {
  some i
  input.resource[i].kind == "Deployment"
  not is_default_namespace(input.resource[i])
}

# POLICY 8--------------------------------->

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a Deployment binds any of its containers to a host port
Deployment_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input Deployment binds one or more of its containers to a host port and return a message
check_deployment_hostport[msg] {
  some i
  input.resource[i].kind == "Deployment"
  Deployment_binds_host_port(input.resource[i])
  msg := "Deployment binds to a host port"
}

# Check if the input Deployment does not bind any of its containers to a host port and return a message
check_deployment_hostport[msg] {
  some i
  input.resource[i].kind == "Deployment"
  not Deployment_binds_host_port(input.resource[i])
  msg := "Deployment does not bind to a host port"
}

# POLICY 9--------------------------------->

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any Job running in the default namespace
deny_job_namespace[msg] {
  some i
  input.resource[i].kind == "Job"
  is_default_namespace(input.resource[i])
  msg = "Job should not run in the default namespace"
}

# Allow Job to run in any namespace except default
allow_job_namespace {
  some i
  input.resource[i].kind == "Job"
  not is_default_namespace(input.resource[i])
}

# POLICY 10--------------------------------->

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a Job binds any of its containers to a host port
Job_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input Job binds one or more of its containers to a host port and return a message
check_Job_hostport[msg] {
  some i
  input.resource[i].kind == "Job"
  Job_binds_host_port(input.resource[i])
  msg := "Job binds to a host port"
}

# Check if the input Job does not bind any of its containers to a host port and return a message
check_Job_hostport[msg] {
  some i
  input.resource[i].kind == "Job"
  not Job_binds_host_port(input.resource[i])
  msg := "Job does not bind to a host port"
}

# POLICY 11--------------------------------->

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any Pod running in the default namespace
deny_Pod_namespace[msg] {
  some i
  input.resource[i].kind == "Pod"
  is_default_namespace(input.resource[i])
  msg = "Pod should not run in the default namespace"
}

# Allow Pod to run in any namespace except default
allow_Pod_namespace {
  some i
  input.resource[i].kind == "Pod"
  not is_default_namespace(input.resource[i])
}

# POLICY 12--------------------------------->

# Check for the existence of `hostAliases` setting in `spec`:

# Define a function to check if a Pod has hostAliases defined
has_host_aliases(pod) {
  pod.spec.hostAliases != null
}

# Deny a Pod if it defines hostAliases and return an error message
deny_pod_host_aliases[msg] {
  some i
  input.resource[i].kind == "Pod"
  has_host_aliases(input.resource[i])
  msg = "Pod should not define hostAliases"
}

# Allow a Pod if it does not define hostAliases
allow_pod_host_aliases {
  some i
  input.resource[i].kind == "Pod"
  not has_host_aliases(input.resource[i])
}

# POLICY 13--------------------------------->

# liveness_probe_set checks if a liveness probe is set for the container using HTTP GET.
liveness_probe_set(container) {
  container.livenessProbe.httpGet != null
}

# liveness_probe_set checks if a liveness probe is set for the container using TCP socket.
liveness_probe_set(container) {
  container.livenessProbe.tcpSocket != null
}

# liveness_probe_set checks if a liveness probe is set for the container using an exec command.
liveness_probe_set(container) {
  container.livenessProbe.exec != null
}

# deny rule to check if a container in a Pod has a liveness probe set. If not, it generates a denial message.
deny_liveness_probe[msg] {
  some i
  input.resource[i].kind == "Pod"          
  container := input.resource[i].spec.containers[_]    
  not liveness_probe_set(container)    
  msg := sprintf("Container '%s' in Pod should set a livenessProbe", [container.name])   
}

# POLICY 14--------------------------------->

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a Pod binds any of its containers to a host port
Pod_binds_host_port(pod) {
  container := pod.spec.containers[_]
  has_host_port(container)
}

# Check if the input Pod binds one or more of its containers to a host port and return a message
check_pod_binds_host_port[msg] {
  some i
  input.resource[i].kind == "Pod"
  Pod_binds_host_port(input.resource[i])
  msg := sprintf("Pod '%s' binds to a host port", [input.resource[i].metadata.name])
}

# Check if the input Pod does not bind any of its containers to a host port and return a message
check_pod_not_bind_host_port[msg] {
  some i
  input.resource[i].kind == "Pod"
  not Pod_binds_host_port(input.resource[i])
  msg := sprintf("Pod '%s' does not bind to a host port", [input.resource[i].metadata.name])
}

# POLICY 15--------------------------------->

# Check if the container has a readinessProbe with httpGet, tcpSocket, or exec.
has_readiness_probe(container) {
  container.readinessProbe.httpGet != null
}

has_readiness_probe(container) {
  container.readinessProbe.tcpSocket != null
}

has_readiness_probe(container) {
  container.readinessProbe.exec != null
}

# Check if at least one container in the Pod has a readinessProbe with httpGet, tcpSocket, or exec.
check_readiness_probe {
  container := input.resource[_].spec.containers[_]
  has_readiness_probe(container)
}

# Deny the Pod if no container has a readinessProbe with httpGet, tcpSocket, or exec.
deny[msg] {
  not check_readiness_probe
  msg := "The container must have a readinessProbe configured with httpGet, tcpSocket, or exec."
}

# POLICY 16--------------------------------->

# Function to check if a container has requested CPU resources
container_has_cpu_request(container) {
  container.resources.requests.cpu != null
}

# Check if the input Pod's containers have requested CPU resources and return a message
check[msg] {
  some i
  input.resource[i].kind == "Pod"
  container := input.resource[i].spec.containers[_]
  container_has_cpu_request(container)
  msg := "Container has requested CPU resources"
}

# Check if the input Pod's containers have not requested CPU resources and return a message
check[msg] {
  some i
  input.resource[i].kind == "Pod"
  container := input.resource[i].spec.containers[_]
  not container_has_cpu_request(container)
  msg := "Container has not requested CPU resources"
}


# Function to check if a container has requested memory resources
container_has_memory_request(container) {
  container.resources.requests.memory != null
}

# Check if the input Pod's containers have requested memory resources and return a message
check[msg] {
  some i
  input.resource[i].kind == "Pod"
  container := input.resource[i].spec.containers[_]
  container_has_memory_request(container)
  msg := "Container has requested memory resources"
}

# Check if the input Pod's containers have not requested memory resources and return a message
check[msg] {
  some i
  input.resource[i].kind == "Pod"
  container := input.resource[i].spec.containers[_]
  not container_has_memory_request(container)
  msg := "Container has not requested memory resources"
}

# POLICY 17--------------------------------->

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any replicaset running in the default namespace
deny_replicaset_namespace[msg] {
  some i
  input.resource[i].kind == "replicaset"
  is_default_namespace(input.resource[i])
  msg = "replicaset should not run in the default namespace"
}

# Allow replicaset to run in any namespace except default
allow_replicaset_namespace {
  some i
  input.resource[i].kind == "replicaset"
  not is_default_namespace(input.resource[i])
}

# POLICY 18--------------------------------->

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a ReplicaSet binds any of its containers to a host port
replicaset_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input ReplicaSet binds one or more of its containers to a host port and return a message
check[msg] {
  some i
  input.resource[i].kind == "ReplicaSet"
  replicaset_binds_host_port(input.resource[i])
  msg := "ReplicaSet binds to a host port"
}

# Check if the input ReplicaSet does not bind any of its containers to a host port and return a message
check[msg] {
  some i
  input.resource[i].kind == "ReplicaSet"
  not replicaset_binds_host_port(input.resource[i])
  msg := "ReplicaSet does not bind to a host port"
}

# POLICY 19--------------------------------->

# Check if a workload is running in the default namespace
is_default_namespace(workload) {
  workload.metadata.namespace == "default"
}

# Deny any StatefulSet running in the default namespace
deny_StatefulSet_namespace[msg] {
  some i
  input.resource[i].kind == "StatefulSet"
  is_default_namespace(input.resource[i])
  msg = "StatefulSet should not run in the default namespace"
}

# Allow StatefulSet to run in any namespace except default
allow_StatefulSet_namespace {
  some i
  input.resource[i].kind == "StatefulSet"
  not is_default_namespace(input.resource[i])
}

# POLICY 20--------------------------------->

# Helper function to check if a container binds to a host port
has_host_port(container) {
  port := container.ports[_]
  port.hostPort
}

# Function to check if a StatefulSet binds any of its containers to a host port
StatefulSet_binds_host_port(rs) {
  container := rs.spec.template.spec.containers[_]
  has_host_port(container)
}

# Check if the input StatefulSet binds one or more of its containers to a host port and return a message
check_StatefulSet_hostport[msg] {
  some i
  input.resource[i].kind == "StatefulSet"
  StatefulSet_binds_host_port(input.resource[i])
  msg := "StatefulSet binds to a host port"
}

# Check if the input StatefulSet does not bind any of its containers to a host port and return a message
check_StatefulSet_hostport[msg] {
  some i
  input.resource[i].kind == "StatefulSet"
  not StatefulSet_binds_host_port(input.resource[i])
  msg := "StatefulSet does not bind to a host port"
}


#Check for the existence of CPU `requests` resources.

package statefulset-requestcpu

default has_cpu_request = false

has_cpu_request {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.resources.requests.cpu
  
}

deny[msg]{

	not has_cpu_request
    msg := "not define"
}


# By specifying the CPU request, you help the Kubernetes scheduler to allocate resources accordingly. It is important to set the CPU request to avoid potential resource contention and performance degradation issues.

# However, it is worth noting that not setting CPU requests does not directly expose your Kubernetes cluster to attackers. Although an attacker cannot exploit this issue directly, it could contribute to a poor resource allocation strategy, leading to resource contention and suboptimal performance of your applications. This could indirectly impact the availability and performance of your services, which could be exploited by attackers through DDoS attacks or other means to amplify the impact on your infrastructure.

# To minimize the risk of resource-related issues and ensure the stability of your applications, it is essential to follow best practices for resource allocation in your Kubernetes workloads.
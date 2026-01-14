// Security Benchmarks and Patterns
const CIS_BENCHMARKS = {
    privileged: { id: 'CIS 5.2.1', title: 'Privileged Container', severity: 'High' },
    allowPrivilegeEscalation: { id: 'CIS 5.2.6', title: 'Allow Privilege Escalation', severity: 'High' },
    runAsRoot: { id: 'CIS 5.2.5', title: 'Run as Root User', severity: 'High' },
    readOnlyRootFS: { id: 'CIS 5.2.7', title: 'Read-only Root Filesystem', severity: 'Medium' },
    capabilities: { id: 'CIS 5.2.8/5.2.9', title: 'Dangerous Capabilities', severity: 'High' },
    resourceLimits: { id: 'CIS 5.1.1', title: 'Resource Limits', severity: 'Medium' },
    imageLatestTag: { id: 'CIS 5.4.1', title: 'Latest Image Tag', severity: 'Medium' },
    hostNamespace: { id: 'CIS 5.2.2/5.2.3/5.2.4', title: 'Host Namespace Sharing', severity: 'High' },
    defaultServiceAccount: { id: 'CIS 5.1.5', title: 'Default Service Account', severity: 'Medium' },
    hostPathVolume: { id: 'CIS 5.3.6', title: 'HostPath Volume', severity: 'High' },
    missingProbes: { id: 'CIS 5.7.4', title: 'Missing Health Probes', severity: 'Medium' },
    networkPolicy: { id: 'CIS 6.3.1', title: 'Network Policy', severity: 'High' },
    secretsEnv: { id: 'CIS 5.5.1', title: 'Secrets in Environment', severity: 'Medium' },
    appArmor: { id: 'CIS 5.2.12', title: 'AppArmor Profile', severity: 'Medium' },
    seccomp: { id: 'CIS 5.2.13', title: 'Seccomp Profile', severity: 'Medium' }
};

const DANGEROUS_CAPABILITIES = [
    'ALL', 'NET_ADMIN', 'NET_RAW', 'SYS_ADMIN', 'SYS_MODULE', 
    'SYS_PTRACE', 'SYS_RAWIO', 'SYS_CHROOT', 'DAC_OVERRIDE',
    'FOWNER', 'SETUID', 'SETGID', 'KILL', 'MKNOD', 'SYS_BOOT',
    'SYS_TIME', 'WAKE_ALARM', 'BLOCK_SUSPEND', 'AUDIT_CONTROL'
];

const SECRET_PATTERNS = [
    { regex: /AKIA[0-9A-Z]{16}/, desc: 'AWS Access Key ID', severity: 'Critical' },
    { regex: /(?:aws_secret_access_key|aws_session_token)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40,}['"]?/, desc: 'AWS Secret Key', severity: 'Critical' },
    { regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----/, desc: 'Private Key', severity: 'Critical' },
    { regex: /ghp_[0-9a-zA-Z]{36}/, desc: 'GitHub Personal Access Token', severity: 'Critical' },
    { regex: /gho_[0-9a-zA-Z]{36}/, desc: 'GitHub OAuth Token', severity: 'Critical' },
    { regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/, desc: 'JWT Token', severity: 'Critical' },
    { regex: /sk-[a-zA-Z0-9]{48}/, desc: 'OpenAI API Key', severity: 'Critical' },
    { regex: /AIza[0-9A-Za-z_-]{35}/, desc: 'Google API Key', severity: 'Critical' },
    { regex: /(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['"]?[^\s'"`;]{8,}/, desc: 'Hardcoded Credential', severity: 'High' }
];

// Advanced Kubernetes security rules
const K8S_SECURITY_RULES = {
    // Container security
    ALLOW_PRIVILEGED_CONTAINERS: false,
    REQUIRE_RESOURCE_LIMITS: true,
    REQUIRE_READ_ONLY_ROOT_FS: false,
    REQUIRE_NON_ROOT_USER: true,
    DROP_ALL_CAPABILITIES: true,
    ALLOWED_CAPABILITIES: [],
    
    // Pod security
    ALLOW_HOST_NETWORK: false,
    ALLOW_HOST_PID: false,
    ALLOW_HOST_IPC: false,
    ALLOW_HOST_PATHS: false,
    REQUIRE_SERVICE_ACCOUNT: true,
    
    // Image security
    ALLOW_LATEST_TAG: false,
    REQUIRE_IMAGE_DIGEST: false,
    ALLOWED_REGISTRIES: [],
    
    // Network security
    REQUIRE_NETWORK_POLICIES: false,
    ALLOW_EXTERNAL_TRAFFIC: true,
    REQUIRE_TLS_INGRESS: true,
    
    // RBAC security
    ALLOW_WILDCARD_RESOURCES: false,
    ALLOW_WILDCARD_VERBS: false,
    ALLOW_CLUSTER_ADMIN: false
};

// Global state
let findings = [];
let currentFilter = 'all';
let autoFixes = [];

// Tab switching
function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(`${tab}-tab`).classList.add('active');
}

// Load sample configuration
function loadSample() {
    const sample = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vulnerable
  template:
    metadata:
      labels:
        app: vulnerable
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
          runAsUser: 0
          capabilities:
            add:
              - SYS_ADMIN
              - NET_ADMIN
        ports:
        - containerPort: 80
        env:
        - name: DB_PASSWORD
          value: "supersecretpassword123"
        - name: API_KEY
          value: "AKIAIOSFODNN7EXAMPLE"
        volumeMounts:
        - name: host-root
          mountPath: /host
      volumes:
      - name: host-root
        hostPath:
          path: /
          type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-service
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 80
  selector:
    app: vulnerable`;
    
    document.getElementById('config-input').value = sample;
    console.log('Sample configuration loaded');
}

// Clear input
function clearInput() {
    document.getElementById('config-input').value = '';
    console.log('Input cleared');
}

// Main scan function
function scanConfiguration() {
    console.log('Starting security scan...');
    const input = document.getElementById('config-input').value.trim();
    
    if (!input) {
        alert('Please enter some configuration to scan');
        console.warn('No input provided');
        return;
    }

    findings = [];
    autoFixes = [];

    try {
        const inputType = document.getElementById('input-type').value;
        let docs;

        if (inputType === 'yaml') {
            docs = jsyaml.loadAll(input);
            console.log(`Parsed ${docs.length} YAML documents`);
        } else {
            docs = [JSON.parse(input)];
            console.log('Parsed JSON document');
        }

        docs.forEach((doc, index) => {
            if (!doc || typeof doc !== 'object') {
                console.warn(`Document ${index} is not a valid object`);
                return;
            }
            
            console.log(`Scanning document ${index + 1}: ${doc.kind || 'Unknown'}`);
            scanDocument(doc);
            scanSecrets(doc);
            checkCompliance(doc);
        });

        console.log(`Scan complete. Found ${findings.length} issues`);
        renderResults();
        renderFixes();
        switchTab('results');
        
    } catch (error) {
        console.error('Scan error:', error);
        alert(`Error parsing configuration: ${error.message}`);
    }
}

// Document scanner
function scanDocument(doc) {
    if (!doc.kind) {
        console.warn('Document has no kind field');
        return;
    }

    switch(doc.kind.toLowerCase()) {
        case 'pod':
            checkPodSecurity(doc);
            break;
        case 'deployment':
        case 'statefulset':
        case 'daemonset':
        case 'replicaset':
            checkWorkloadSecurity(doc);
            break;
        case 'service':
            checkServiceSecurity(doc);
            break;
        case 'ingress':
            checkIngressSecurity(doc);
            break;
        case 'networkpolicy':
            checkNetworkPolicy(doc);
            break;
        case 'role':
        case 'clusterrole':
        case 'rolebinding':
        case 'clusterrolebinding':
            checkRBAC(doc);
            break;
        case 'secret':
            checkSecret(doc);
            break;
        case 'configmap':
            checkConfigMap(doc);
            break;
        case 'serviceaccount':
            checkServiceAccount(doc);
            break;
        case 'persistentvolume':
        case 'persistentvolumeclaim':
            checkStorageSecurity(doc);
            break;
        default:
            checkGenericResource(doc);
    }
}

// Advanced compliance checking
function checkCompliance(doc) {
    // NIST SP 800-190 compliance checks
    if (doc.spec?.template?.spec?.containers) {
        doc.spec.template.spec.containers.forEach(container => {
            // Check for immutable infrastructure compliance
            if (container.image && container.image.includes(':latest')) {
                addFinding('immutable-infra', `Container uses mutable image tag`, doc.metadata?.name, doc.kind, 'Medium');
            }
            
            // Check for defense in depth
            if (!container.securityContext) {
                addFinding('defense-in-depth', `Container missing security context`, doc.metadata?.name, doc.kind, 'Medium');
            }
        });
    }
    
    // CIS Kubernetes Benchmark compliance
    if (doc.kind === 'Pod' || doc.kind === 'Deployment') {
        const spec = doc.spec?.template?.spec || doc.spec;
        if (spec && !spec.securityContext?.runAsNonRoot) {
            addFinding('cis-5.2.5', `Pod does not enforce runAsNonRoot`, doc.metadata?.name, doc.kind, 'High');
        }
    }
}

// Pod security checks
function checkPodSecurity(pod) {
    const spec = pod.spec || {};
    const resourceName = pod.metadata?.name || 'Unknown';
    const podLineInfo = findLineInfo(pod, 'kind', 'Pod');

    console.log(`Checking pod security for: ${resourceName}`);

    // Host namespaces
    if (spec.hostNetwork) {
        addFinding('hostNamespace', `Pod shares host network namespace`, resourceName, pod.kind, 'High', podLineInfo);
        addAutoFix(pod, 'spec.hostNetwork', false);
    }
    if (spec.hostPID) {
        addFinding('hostNamespace', `Pod shares host PID namespace`, resourceName, pod.kind, 'High', podLineInfo);
        addAutoFix(pod, 'spec.hostPID', false);
    }
    if (spec.hostIPC) {
        addFinding('hostNamespace', `Pod shares host IPC namespace`, resourceName, pod.kind, 'High', podLineInfo);
        addAutoFix(pod, 'spec.hostIPC', false);
    }

    // Service account
    if (!spec.serviceAccountName || spec.serviceAccountName === 'default') {
        addFinding('defaultServiceAccount', `Pod uses default service account`, resourceName, pod.kind, 'Medium', podLineInfo);
        addAutoFix(pod, 'spec.serviceAccountName', 'custom-service-account');
    }

    // Automount service account token
    if (spec.automountServiceAccountToken !== false) {
        addFinding('defaultServiceAccount', `Pod automatically mounts service account token`, resourceName, pod.kind, 'Medium', podLineInfo);
        addAutoFix(pod, 'spec.automountServiceAccountToken', false);
    }

    // Containers
    const containers = [...(spec.containers || []), ...(spec.initContainers || [])];
    containers.forEach((container, index) => {
        const containerLineInfo = findLineInfo(spec.containers || spec.initContainers, index, container.name);
        checkContainerSecurity(container, resourceName, pod.kind, containerLineInfo);
    });

    // Volumes
    if (spec.volumes) {
        spec.volumes.forEach((vol, index) => {
            const volLineInfo = findLineInfo(spec.volumes, index, vol.name);
            if (vol.hostPath) {
                addFinding('hostPathVolume', `Pod uses hostPath volume: ${vol.name}`, resourceName, pod.kind, 'High', volLineInfo);
            }
            if (vol.emptyDir && vol.emptyDir.medium === 'Memory') {
                addFinding('memory-volume', `Pod uses memory-backed emptyDir volume`, resourceName, pod.kind, 'Medium', volLineInfo);
            }
        });
    }

    // Security context
    if (spec.securityContext) {
        const secCtxLineInfo = findLineInfo(spec, 'securityContext');
        if (!spec.securityContext.runAsNonRoot) {
            addFinding('runAsRoot', `Pod does not enforce runAsNonRoot`, resourceName, pod.kind, 'High', secCtxLineInfo);
            addAutoFix(pod, 'spec.securityContext.runAsNonRoot', true);
        }
        if (!spec.securityContext.seccompProfile || spec.securityContext.seccompProfile.type !== 'RuntimeDefault') {
            addFinding('seccomp', `Pod missing seccomp profile`, resourceName, pod.kind, 'Medium', secCtxLineInfo);
            addAutoFix(pod, 'spec.securityContext.seccompProfile', { type: 'RuntimeDefault' });
        }
    } else {
        const specLineInfo = findLineInfo(pod, 'spec');
        addFinding('security-context', `Pod missing security context`, resourceName, pod.kind, 'Medium', specLineInfo);
        addAutoFix(pod, 'spec.securityContext', {
            runAsNonRoot: true,
            seccompProfile: { type: 'RuntimeDefault' }
        });
    }

    // Node selector/affinity checks
    if (spec.nodeSelector || spec.affinity) {
        checkNodeSecurity(spec, resourceName, pod.kind, podLineInfo);
    }
}

// Workload security checks
function checkWorkloadSecurity(workload) {
    const template = workload.spec?.template;
    if (template) {
        checkPodSecurity({
            kind: 'Pod',
            metadata: { name: workload.metadata?.name },
            spec: template.spec
        });
    }
    
    // Workload-specific checks
    if (workload.kind === 'Deployment') {
        const workloadLineInfo = findLineInfo(workload, 'kind', 'Deployment');
        if (workload.spec?.strategy?.type === 'Recreate') {
            addFinding('deployment-strategy', `Deployment uses Recreate strategy (causes downtime)`, workload.metadata?.name, workload.kind, 'Low', workloadLineInfo);
        }
    }
}

// Container security checks
function checkContainerSecurity(container, resourceName, kind, lineInfo) {
    const ctx = container.securityContext || {};
    const name = container.name;

    console.log(`Checking container: ${name}`);

    // Privileged
    if (ctx.privileged) {
        addFinding('privileged', `Container '${name}' runs in privileged mode`, resourceName, kind, 'High', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.privileged', false);
    }

    // Privilege escalation
    if (ctx.allowPrivilegeEscalation !== false) {
        addFinding('allowPrivilegeEscalation', `Container '${name}' allows privilege escalation`, resourceName, kind, 'High', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.allowPrivilegeEscalation', false);
    }

    // Root user
    if (ctx.runAsUser === 0) {
        addFinding('runAsRoot', `Container '${name}' runs as root (UID 0)`, resourceName, kind, 'High', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.runAsUser', 1000);
    }

    // Read-only root filesystem
    if (!ctx.readOnlyRootFilesystem) {
        addFinding('readOnlyRootFS', `Container '${name}' has writable root filesystem`, resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.readOnlyRootFilesystem', true);
    }

    // Capabilities
    if (ctx.capabilities?.add) {
        const dangerous = ctx.capabilities.add.filter(cap => 
            DANGEROUS_CAPABILITIES.includes(cap.toUpperCase())
        );
        if (dangerous.length > 0) {
            addFinding('capabilities', `Container '${name}' has dangerous capabilities: ${dangerous.join(', ')}`, resourceName, kind, 'High', lineInfo);
            addAutoFixForContainer(resourceName, kind, container, 'securityContext.capabilities.add', 
                ctx.capabilities.add.filter(cap => !DANGEROUS_CAPABILITIES.includes(cap.toUpperCase()))
            );
        }
    }
    
    if (!ctx.capabilities?.drop?.includes('ALL')) {
        addFinding('capabilities', `Container '${name}' does not drop all capabilities`, resourceName, kind, 'Medium', lineInfo);
        const newDrop = ctx.capabilities?.drop || [];
        if (!newDrop.includes('ALL')) newDrop.push('ALL');
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.capabilities.drop', newDrop);
    }

    // Resource limits
    if (!container.resources?.limits) {
        addFinding('resourceLimits', `Container '${name}' has no resource limits`, resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'resources.limits', {
            cpu: '500m',
            memory: '512Mi'
        });
    } else {
        if (!container.resources.limits.cpu) {
            addFinding('resourceLimits', `Container '${name}' has no CPU limit`, resourceName, kind, 'Medium', lineInfo);
            addAutoFixForContainer(resourceName, kind, container, 'resources.limits.cpu', '500m');
        }
        if (!container.resources.limits.memory) {
            addFinding('resourceLimits', `Container '${name}' has no memory limit`, resourceName, kind, 'Medium', lineInfo);
            addAutoFixForContainer(resourceName, kind, container, 'resources.limits.memory', '512Mi');
        }
    }
    
    if (!container.resources?.requests) {
        addFinding('resource-requests', `Container '${name}' has no resource requests`, resourceName, kind, 'Low', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'resources.requests', {
            cpu: '100m',
            memory: '128Mi'
        });
    }

    // Health probes
    if (!container.livenessProbe) {
        addFinding('missingProbes', `Container '${name}' missing liveness probe`, resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'livenessProbe', {
            httpGet: { path: '/healthz', port: 8080 },
            initialDelaySeconds: 15,
            periodSeconds: 10
        });
    }
    if (!container.readinessProbe) {
        addFinding('missingProbes', `Container '${name}' missing readiness probe`, resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'readinessProbe', {
            httpGet: { path: '/ready', port: 8080 },
            initialDelaySeconds: 5,
            periodSeconds: 5
        });
    }

    // Image tag
    if (container.image && (container.image.endsWith(':latest') || !container.image.includes(':'))) {
        addFinding('imageLatestTag', `Container '${name}' uses 'latest' or no tag`, resourceName, kind, 'Medium', lineInfo);
    }
    
    if (container.image && !container.image.includes('@sha256:')) {
        addFinding('image-digest', `Container '${name}' not using immutable image digest`, resourceName, kind, 'Low', lineInfo);
    }

    // Environment variables
    if (container.env) {
        container.env.forEach((envVar, index) => {
            const envLineInfo = findLineInfo(container.env, index, envVar.name);
            if (envVar.valueFrom?.secretKeyRef) {
                addFinding('secretsEnv', `Container '${name}' uses secret in env var '${envVar.name}'`, resourceName, kind, 'Medium', envLineInfo);
            }
            if (envVar.value && (envVar.name.toLowerCase().includes('password') || 
                envVar.name.toLowerCase().includes('secret') || 
                envVar.name.toLowerCase().includes('key'))) {
                addFinding('hardcoded-env', `Container '${name}' has potentially sensitive env var '${envVar.name}'`, resourceName, kind, 'High', envLineInfo);
            }
        });
    }

    // Ports configuration
    if (container.ports) {
        container.ports.forEach((port, index) => {
            const portLineInfo = findLineInfo(container.ports, index, port.containerPort);
            if (port.hostPort) {
                addFinding('host-port', `Container '${name}' uses hostPort: ${port.hostPort}`, resourceName, kind, 'Medium', portLineInfo);
            }
        });
    }
}

// Node security checks
function checkNodeSecurity(spec, resourceName, kind, lineInfo) {
    if (spec.nodeSelector && Object.keys(spec.nodeSelector).length === 0) {
        addFinding('node-selector', `Resource has empty nodeSelector`, resourceName, kind, 'Info', lineInfo);
    }
}

// Service security checks
function checkServiceSecurity(svc) {
    const resourceName = svc.metadata?.name || 'Unknown';
    const svcLineInfo = findLineInfo(svc, 'kind', 'Service');
    
    console.log(`Checking service: ${resourceName}`);
    
    if (svc.spec?.type === 'LoadBalancer') {
        addFinding('Service-LoadBalancer', `Service exposes LoadBalancer publicly`, resourceName, svc.kind, 'Medium', svcLineInfo);
    }
    
    if (svc.spec?.externalIPs?.length > 0) {
        addFinding('Service-ExternalIP', `Service uses external IPs: ${svc.spec.externalIPs.join(', ')}`, resourceName, svc.kind, 'High', svcLineInfo);
        addAutoFix(svc, 'spec.externalIPs', []);
    }
    
    if (svc.spec?.externalTrafficPolicy === 'Cluster') {
        addFinding('external-traffic', `Service uses Cluster external traffic policy (may lose source IP)`, resourceName, svc.kind, 'Low', svcLineInfo);
    }
    
    // Check for NodePort usage
    if (svc.spec?.type === 'NodePort') {
        addFinding('node-port', `Service uses NodePort type`, resourceName, svc.kind, 'Medium', svcLineInfo);
    }
}

// Ingress security checks
function checkIngressSecurity(ingress) {
    const resourceName = ingress.metadata?.name || 'Unknown';
    const ingressLineInfo = findLineInfo(ingress, 'kind', 'Ingress');
    
    console.log(`Checking ingress: ${resourceName}`);
    
    if (!ingress.spec?.tls || ingress.spec.tls.length === 0) {
        addFinding('Ingress-NoTLS', `Ingress does not enforce TLS`, resourceName, ingress.kind, 'High', ingressLineInfo);
    }
    
    // Check for wildcard hosts
    if (ingress.spec?.rules) {
        ingress.spec.rules.forEach((rule, index) => {
            const ruleLineInfo = findLineInfo(ingress.spec.rules, index, rule.host);
            if (rule.host && rule.host.startsWith('*.')) {
                addFinding('wildcard-host', `Ingress uses wildcard host: ${rule.host}`, resourceName, ingress.kind, 'Medium', ruleLineInfo);
            }
        });
    }
    
    // Check ingress class
    if (ingress.spec?.ingressClassName) {
        addFinding('ingress-class', `Ingress uses specific ingress class: ${ingress.spec.ingressClassName}`, resourceName, ingress.kind, 'Info', ingressLineInfo);
    }
}

// Network policy checks
function checkNetworkPolicy(policy) {
    const resourceName = policy.metadata?.name || 'Unknown';
    const policyLineInfo = findLineInfo(policy, 'kind', 'NetworkPolicy');
    
    console.log(`Checking network policy: ${resourceName}`);
    
    if (!policy.spec?.ingress) {
        addFinding('networkPolicy', `NetworkPolicy has no ingress rules`, resourceName, policy.kind, 'High', policyLineInfo);
        addAutoFix(policy, 'spec.ingress', [{}]);
    }
    
    if (!policy.spec?.egress) {
        addFinding('networkPolicy', `NetworkPolicy has no egress rules`, resourceName, policy.kind, 'Medium', policyLineInfo);
        addAutoFix(policy, 'spec.egress', [{}]);
    }
    
    // Check policy types
    if (!policy.spec?.policyTypes) {
        addFinding('policy-types', `NetworkPolicy missing policyTypes`, resourceName, policy.kind, 'Medium', policyLineInfo);
    }
}

// RBAC checks
function checkRBAC(role) {
    const resourceName = role.metadata?.name || 'Unknown';
    const roleLineInfo = findLineInfo(role, 'kind', role.kind);
    
    console.log(`Checking RBAC: ${resourceName}`);
    
    if (role.rules) {
        role.rules.forEach((rule, index) => {
            const ruleLineInfo = findLineInfo(role.rules, index);
            if (rule.resources?.includes('*')) {
                addFinding('RBAC-Wildcard', `${role.kind} allows wildcard resources`, resourceName, role.kind, 'High', ruleLineInfo);
            }
            if (rule.verbs?.includes('*')) {
                addFinding('RBAC-Wildcard', `${role.kind} allows wildcard verbs`, resourceName, role.kind, 'High', ruleLineInfo);
            }
            if (rule.apiGroups?.includes('*')) {
                addFinding('RBAC-Wildcard', `${role.kind} allows wildcard API groups`, resourceName, role.kind, 'High', ruleLineInfo);
            }
            
            // Check for dangerous permissions
            const dangerousVerbs = ['*', 'create', 'update', 'patch', 'delete'];
            const dangerousResources = ['*', 'pods', 'secrets', 'configmaps', 'services'];
            
            const hasDangerous = rule.verbs?.some(v => dangerousVerbs.includes(v)) &&
                                 rule.resources?.some(r => dangerousResources.includes(r));
            
            if (hasDangerous) {
                addFinding('dangerous-rbac', `${role.kind} has potentially dangerous permissions`, resourceName, role.kind, 'High', ruleLineInfo);
            }
        });
    }
    
    // Check for cluster-admin
    if (role.metadata?.name === 'cluster-admin' && role.kind === 'ClusterRole') {
        addFinding('cluster-admin', `ClusterRole 'cluster-admin' is extremely privileged`, resourceName, role.kind, 'Critical', roleLineInfo);
    }
}

// Secret checks
function checkSecret(secret) {
    const resourceName = secret.metadata?.name || 'Unknown';
    const secretLineInfo = findLineInfo(secret, 'kind', 'Secret');
    
    console.log(`Checking secret: ${resourceName}`);
    
    if (secret.data) {
        Object.keys(secret.data).forEach((key, index) => {
            const keyLineInfo = findLineInfo(secret.data, key);
            try {
                const decoded = atob(secret.data[key]);
                SECRET_PATTERNS.forEach(pattern => {
                    if (pattern.regex.test(decoded)) {
                        addFinding('Secret-Exposed', `Secret contains ${pattern.desc} in key '${key}'`, resourceName, secret.kind, 'Critical', keyLineInfo);
                    }
                });
            } catch (e) {
                // Invalid base64
                addFinding('invalid-base64', `Secret key '${key}' contains invalid base64 data`, resourceName, secret.kind, 'Low', keyLineInfo);
            }
        });
    }
    
    if (secret.stringData) {
        Object.keys(secret.stringData).forEach(key => {
            const value = secret.stringData[key];
            SECRET_PATTERNS.forEach(pattern => {
                if (pattern.regex.test(value)) {
                    addFinding('stringdata-secret', `Secret stringData contains ${pattern.desc} in key '${key}'`, resourceName, secret.kind, 'Critical', secretLineInfo);
                }
            });
        });
    }
    
    // Check secret type
    if (secret.type === 'Opaque') {
        addFinding('opaque-secret', `Secret uses Opaque type (consider using specific type)`, resourceName, secret.kind, 'Low', secretLineInfo);
    }
}

// ConfigMap checks
function checkConfigMap(configMap) {
    const resourceName = configMap.metadata?.name || 'Unknown';
    const cmLineInfo = findLineInfo(configMap, 'kind', 'ConfigMap');
    
    console.log(`Checking configmap: ${resourceName}`);
    
    if (configMap.data) {
        Object.entries(configMap.data).forEach(([key, value]) => {
            const valueLineInfo = findLineInfo(configMap.data, key);
            SECRET_PATTERNS.forEach(pattern => {
                if (pattern.regex.test(value)) {
                    addFinding('ConfigMap-Secret', `ConfigMap contains ${pattern.desc} in key '${key}'`, resourceName, configMap.kind, 'High', valueLineInfo);
                }
            });
        });
    }
    
    if (configMap.binaryData) {
        addFinding('binary-data', `ConfigMap uses binaryData field`, resourceName, configMap.kind, 'Info', cmLineInfo);
    }
}

// Service Account checks
function checkServiceAccount(sa) {
    const resourceName = sa.metadata?.name || 'Unknown';
    const saLineInfo = findLineInfo(sa, 'kind', 'ServiceAccount');
    
    console.log(`Checking service account: ${resourceName}`);
    
    if (sa.automountServiceAccountToken === undefined || sa.automountServiceAccountToken === true) {
        addFinding('auto-mount-token', `ServiceAccount automatically mounts token`, resourceName, sa.kind, 'Medium', saLineInfo);
        addAutoFix(sa, 'automountServiceAccountToken', false);
    }
    
    if (sa.imagePullSecrets && sa.imagePullSecrets.length > 0) {
        addFinding('image-pull-secrets', `ServiceAccount has image pull secrets`, resourceName, sa.kind, 'Info', saLineInfo);
    }
}

// Storage security checks
function checkStorageSecurity(storage) {
    const resourceName = storage.metadata?.name || 'Unknown';
    const storageLineInfo = findLineInfo(storage, 'kind', storage.kind);
    
    console.log(`Checking storage: ${resourceName}`);
    
    if (storage.kind === 'PersistentVolume') {
        if (storage.spec?.hostPath) {
            addFinding('hostpath-pv', `PersistentVolume uses hostPath`, resourceName, storage.kind, 'High', storageLineInfo);
        }
        
        if (storage.spec?.accessModes?.includes('ReadWriteMany')) {
            addFinding('rwx-access', `PersistentVolume allows ReadWriteMany access`, resourceName, storage.kind, 'Medium', storageLineInfo);
        }
    }
    
    if (storage.kind === 'PersistentVolumeClaim') {
        if (storage.spec?.storageClassName === '') {
            addFinding('default-storage', `PersistentVolumeClaim uses default storage class`, resourceName, storage.kind, 'Low', storageLineInfo);
        }
    }
}

// Generic resource checks
function checkGenericResource(resource) {
    const resourceName = resource.metadata?.name || 'Unknown';
    const resourceLineInfo = findLineInfo(resource, 'kind', resource.kind);
    
    // Check namespace
    if (resource.metadata && !resource.metadata.namespace && 
        resource.kind !== 'Namespace' && resource.kind !== 'ClusterRole' && 
        resource.kind !== 'ClusterRoleBinding' && resource.kind !== 'PersistentVolume') {
        addFinding('missing-namespace', `${resource.kind} not assigned to namespace`, resourceName, resource.kind, 'Low', resourceLineInfo);
    }
    
    // Check labels
    if (resource.metadata && (!resource.metadata.labels || Object.keys(resource.metadata.labels).length === 0)) {
        addFinding('missing-labels', `${resource.kind} has no labels`, resourceName, resource.kind, 'Info', resourceLineInfo);
    }
    
    // Check annotations for security context
    if (resource.metadata?.annotations) {
        checkSecurityAnnotations(resource.metadata.annotations, resourceName, resource.kind, resourceLineInfo);
    }
}

// Check security annotations
function checkSecurityAnnotations(annotations, resourceName, kind, lineInfo) {
    // Check for Pod Security Standards
    if (annotations['pod-security.kubernetes.io/enforce']) {
        addFinding('pss-enforced', `${kind} has Pod Security Standard enforced`, resourceName, kind, 'Info', lineInfo);
    }
    
    // Check for deprecated annotations
    const deprecatedAnnotations = [
        'kubernetes.io/ingress.class',
        'helm.sh/hook',
        'sidecar.istio.io/inject'
    ];
    
    deprecatedAnnotations.forEach(deprecated => {
        if (annotations[deprecated]) {
            addFinding('deprecated-annotation', `${kind} uses deprecated annotation: ${deprecated}`, resourceName, kind, 'Low', lineInfo);
        }
    });
}

// Secret pattern scanning
function scanSecrets(doc) {
    const docString = JSON.stringify(doc);
    const resourceName = doc.metadata?.name || 'Unknown';
    const docLineInfo = findLineInfo(doc, 'kind', doc.kind);
    
    SECRET_PATTERNS.forEach(pattern => {
        const matches = docString.match(new RegExp(pattern.regex, 'g'));
        if (matches) {
            matches.slice(0, 3).forEach(match => {
                addFinding('Hardcoded-Secret', `${pattern.desc}: ${match.substring(0, 20)}...`, resourceName, doc.kind || 'Unknown', pattern.severity, docLineInfo);
            });
        }
    });
}

// Add finding to results
function addFinding(type, message, resource, kind, customSeverity = null, lineInfo = null) {
    const benchmark = CIS_BENCHMARKS[type];
    const id = benchmark?.

// ============================================
// ADVANCED KUBERNETES SECURITY SCANNER
// ============================================

// Security Benchmarks and Patterns
const CIS_BENCHMARKS = {
    // Container Security
    privileged: { id: 'CIS 5.2.1', title: 'Privileged Container', severity: 'High' },
    allowPrivilegeEscalation: { id: 'CIS 5.2.6', title: 'Allow Privilege Escalation', severity: 'High' },
    runAsRoot: { id: 'CIS 5.2.5', title: 'Run as Root User', severity: 'High' },
    readOnlyRootFS: { id: 'CIS 5.2.7', title: 'Read-only Root Filesystem', severity: 'Medium' },
    capabilities: { id: 'CIS 5.2.8/5.2.9', title: 'Dangerous Capabilities', severity: 'High' },
    seLinuxOptions: { id: 'CIS 5.2.10', title: 'SELinux Context Options', severity: 'Medium' },
    procMount: { id: 'CIS 5.2.11', title: '/proc Mount Type', severity: 'Medium' },
    
    // Resource Management
    resourceLimits: { id: 'CIS 5.1.1', title: 'Resource Limits', severity: 'Medium' },
    resourceLimitsCPU: { id: 'CIS 5.1.2', title: 'CPU Limits', severity: 'Medium' },
    resourceLimitsMemory: { id: 'CIS 5.1.3', title: 'Memory Limits', severity: 'Medium' },
    
    // Image Management
    imageLatestTag: { id: 'CIS 5.4.1', title: 'Latest Image Tag', severity: 'Medium' },
    imageDigest: { id: 'CIS 5.4.2', title: 'Image Digest', severity: 'Low' },
    
    // Pod Security
    hostNamespace: { id: 'CIS 5.2.2/5.2.3/5.2.4', title: 'Host Namespace Sharing', severity: 'High' },
    defaultServiceAccount: { id: 'CIS 5.1.5', title: 'Default Service Account', severity: 'Medium' },
    hostPathVolume: { id: 'CIS 5.3.6', title: 'HostPath Volume', severity: 'High' },
    missingProbes: { id: 'CIS 5.7.4', title: 'Missing Health Probes', severity: 'Medium' },
    
    // Network Security
    networkPolicy: { id: 'CIS 6.3.1', title: 'Network Policy', severity: 'High' },
    hostPort: { id: 'CIS 5.3.5', title: 'Host Port Usage', severity: 'Medium' },
    
    // Secrets Management
    secretsEnv: { id: 'CIS 5.5.1', title: 'Secrets in Environment Variables', severity: 'Medium' },
    secretsVolume: { id: 'CIS 5.5.2', title: 'Secrets Mounted as Volumes', severity: 'Low' },
    
    // General Security
    appArmor: { id: 'CIS 5.2.12', title: 'AppArmor Profile', severity: 'Medium' },
    seccomp: { id: 'CIS 5.2.13', title: 'Seccomp Profile', severity: 'Medium' },
    podSecurityPolicy: { id: 'CIS 5.2.14', title: 'Pod Security Policy', severity: 'High' }
};

const DANGEROUS_CAPABILITIES = [
    'ALL', 'NET_ADMIN', 'NET_RAW', 'SYS_ADMIN', 'SYS_MODULE', 
    'SYS_PTRACE', 'SYS_RAWIO', 'SYS_CHROOT', 'DAC_OVERRIDE',
    'FOWNER', 'SETUID', 'SETGID', 'KILL', 'MKNOD', 'SYS_BOOT',
    'SYS_TIME', 'WAKE_ALARM', 'BLOCK_SUSPEND', 'AUDIT_CONTROL',
    'MAC_ADMIN', 'MAC_OVERRIDE', 'IPC_LOCK', 'LEASE'
];

const SECRET_PATTERNS = [
    { regex: /AKIA[0-9A-Z]{16}/, desc: 'AWS Access Key ID', severity: 'Critical' },
    { regex: /[0-9a-zA-Z/+]{40}/, desc: 'AWS Secret Access Key', severity: 'Critical' },
    { regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----/, desc: 'Private Key', severity: 'Critical' },
    { regex: /-----BEGIN CERTIFICATE-----/, desc: 'Certificate', severity: 'High' },
    { regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/, desc: 'JWT Token', severity: 'Critical' },
    { regex: /ghp_[0-9a-zA-Z]{36}/, desc: 'GitHub Personal Access Token', severity: 'Critical' },
    { regex: /gho_[0-9a-zA-Z]{36}/, desc: 'GitHub OAuth Token', severity: 'Critical' },
    { regex: /sk-[a-zA-Z0-9]{48}/, desc: 'OpenAI API Key', severity: 'Critical' },
    { regex: /AIza[0-9A-Za-z_-]{35}/, desc: 'Google API Key', severity: 'Critical' },
    { regex: /xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/, desc: 'Slack Token', severity: 'Critical' },
    { regex: /(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['"]?[^\s'"`;]{8,}/, desc: 'Hardcoded Credential', severity: 'High' },
    { regex: /(?:database|db)[^a-zA-Z0-9].*(?:password|pwd|user|url)/i, desc: 'Database credential', severity: 'High' },
    { regex: /(?:http|https):\/\/[^\s]+@[^\s]+/, desc: 'URL with credentials', severity: 'Critical' }
];

// NIST SP 800-190 Compliance Checks
const NIST_COMPLIANCE = {
    'IM-1': 'Use trusted base images',
    'IM-2': 'Scan images for vulnerabilities',
    'IM-3': 'Sign and verify images',
    'IM-4': 'Use immutable image references',
    'CM-1': 'Use least privilege',
    'CM-2': 'Limit container capabilities',
    'CM-3': 'Prevent privileged containers',
    'CM-4': 'Prevent root user',
    'CM-5': 'Use read-only root filesystem',
    'CM-6': 'Use namespaces',
    'CM-7': 'Limit host access',
    'CM-8': 'Limit network access',
    'PS-1': 'Use resource limits',
    'PS-2': 'Monitor container resources',
    'PS-3': 'Limit container lifetime',
    'PS-4': 'Use health checks',
    'NS-1': 'Isolate container networks',
    'NS-2': 'Limit network traffic',
    'NS-3': 'Encrypt network traffic',
    'NS-4': 'Authenticate network connections'
};

// Global state
let findings = [];
let currentFilter = 'all';
let originalConfig = '';
let configLines = [];
let autoFixes = [];

// ============================================
// UI FUNCTIONS
// ============================================

// Tab switching
function switchTab(tab) {
    // Remove active class from all tab buttons
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Remove active class from all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
    });
    
    // Add active class to clicked tab button
    const clickedTab = event.target;
    clickedTab.classList.add('active');
    
    // Show the selected tab content
    document.getElementById(`${tab}-tab`).classList.add('active');
    
    console.log(`Switched to tab: ${tab}`);
}

// Load sample configuration
function loadSample() {
    const sample = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: default
  labels:
    app: vulnerable
    env: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vulnerable
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: vulnerable
        version: v1.0.0
    spec:
      securityContext:
        runAsNonRoot: false
        seccompProfile:
          type: Unconfined
      hostNetwork: true
      hostPID: true
      hostIPC: true
      serviceAccountName: default
      automountServiceAccountToken: true
      containers:
      - name: app
        image: nginx:latest
        imagePullPolicy: Always
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
          runAsUser: 0
          runAsGroup: 0
          readOnlyRootFilesystem: false
          capabilities:
            add:
              - SYS_ADMIN
              - NET_ADMIN
              - SYS_PTRACE
              - DAC_OVERRIDE
            drop:
              - NET_BIND_SERVICE
        ports:
        - containerPort: 80
          hostPort: 8080
          protocol: TCP
        - containerPort: 443
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
        env:
        - name: DB_PASSWORD
          value: "SuperSecretDBPassword123!"
        - name: AWS_ACCESS_KEY_ID
          value: "AKIAIOSFODNN7EXAMPLE"
        - name: JWT_TOKEN
          value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: api-key
        volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: false
        - name: secrets
          mountPath: /etc/secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5
      initContainers:
      - name: init-db
        image: busybox:latest
        command: ['sh', '-c', 'echo "Initializing database..."']
        securityContext:
          runAsUser: 0
      volumes:
      - name: host-root
        hostPath:
          path: /
          type: Directory
      - name: secrets
        secret:
          secretName: app-secrets
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-service
  namespace: default
spec:
  type: LoadBalancer
  externalIPs:
    - 203.0.113.10
    - 198.51.100.20
  ports:
  - name: http
    port: 80
    targetPort: 80
    protocol: TCP
  - name: https
    port: 443
    targetPort: 443
    protocol: TCP
  selector:
    app: vulnerable
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - {}
  egress:
  - {}
---
apiVersion: v1
kind: Secret
metadata:
  name: api-secrets
  namespace: default
type: Opaque
data:
  api-key: YXBpLWtleS1zZWNyZXQtdmFsdWU=
  password: c3VwZXItc2VjcmV0LXBhc3N3b3Jk
stringData:
  token: "plaintext-token-value"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  config.json: |
    {
      "database": {
        "host": "localhost",
        "port": 5432,
        "username": "admin",
        "password": "db-admin-password-123",
        "ssl": true
      },
      "api": {
        "endpoint": "https://api.example.com",
        "key": "abcdef1234567890"
      }
    }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vulnerable-ingress
  namespace: default
spec:
  rules:
  - host: "*.example.com"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: vulnerable-service
            port:
              number: 80
  tls: []`;
    
    document.getElementById('config-input').value = sample;
    console.log('Sample configuration loaded');
}

// Clear input
function clearInput() {
    document.getElementById('config-input').value = '';
    console.log('Input cleared');
}

// ============================================
// MAIN SCANNING FUNCTION
// ============================================

function scanConfiguration() {
    console.log('Starting advanced security scan...');
    
    const input = document.getElementById('config-input').value.trim();
    
    if (!input) {
        alert('Please enter some configuration to scan');
        console.warn('No input provided');
        return;
    }

    // Reset state
    findings = [];
    originalConfig = input;
    configLines = input.split('\n');
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
            
            // Comprehensive security scanning
            scanDocument(doc);
            scanSecrets(doc);
            checkNISTCompliance(doc);
            checkDockerComposeSecurity(doc);
            
            // Advanced security checks
            checkAdvancedSecurity(doc);
        });

        console.log(`Scan complete. Found ${findings.length} security issues`);
        
        // Render results
        renderResults();
        renderFixes();
        
        // Switch to results tab
        switchTab('results');
        
    } catch (error) {
        console.error('Scan error:', error);
        alert(`Error parsing configuration: ${error.message}\n\nPlease check your YAML/JSON syntax.`);
    }
}

// ============================================
// ADVANCED SECURITY CHECKS
// ============================================

function scanDocument(doc) {
    if (!doc.kind && !doc.version) {
        console.warn('Document has no kind/version field');
        checkGenericSecurity(doc);
        return;
    }

    if (doc.kind) {
        switch(doc.kind.toLowerCase()) {
            case 'pod':
                checkPodSecurity(doc);
                break;
            case 'deployment':
            case 'statefulset':
            case 'daemonset':
            case 'replicaset':
            case 'job':
            case 'cronjob':
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
                checkSecretSecurity(doc);
                break;
            case 'configmap':
                checkConfigMapSecurity(doc);
                break;
            case 'serviceaccount':
                checkServiceAccountSecurity(doc);
                break;
            case 'podsecuritypolicy':
                checkPodSecurityPolicy(doc);
                break;
            case 'persistentvolume':
            case 'persistentvolumeclaim':
                checkStorageSecurity(doc);
                break;
            case 'horizontalpodautoscaler':
                checkHPASecurity(doc);
                break;
            default:
                checkGenericResourceSecurity(doc);
        }
    }
}

// Advanced security checks
function checkAdvancedSecurity(doc) {
    // Check for deprecated APIs
    checkDeprecatedAPIs(doc);
    
    // Check for beta/alpha features
    checkBetaFeatures(doc);
    
    // Check for pod security standards
    checkPodSecurityStandards(doc);
    
    // Check for container runtime security
    checkContainerRuntimeSecurity(doc);
    
    // Check for cloud provider specific security
    checkCloudProviderSecurity(doc);
}

// NIST Compliance checks
function checkNISTCompliance(doc) {
    const lineInfo = findLineInfo(doc, 'kind', doc.kind);
    
    // IM-1: Use trusted base images
    if (doc.spec?.template?.spec?.containers) {
        doc.spec.template.spec.containers.forEach(container => {
            if (container.image && container.image.includes('nginx:latest')) {
                addFinding('NIST-IM-1', 'Using untrusted base image with latest tag', 
                          doc.metadata?.name || 'Unknown', doc.kind || 'Unknown', 
                          'Medium', lineInfo, 'Use specific, trusted image tags from verified registries');
            }
        });
    }
    
    // CM-1: Use least privilege
    if (doc.spec?.template?.spec?.containers) {
        doc.spec.template.spec.containers.forEach(container => {
            if (container.securityContext?.privileged) {
                addFinding('NIST-CM-1', 'Container violates least privilege principle', 
                          doc.metadata?.name || 'Unknown', doc.kind || 'Unknown', 
                          'High', lineInfo, 'Remove privileged mode and use minimal required capabilities');
            }
        });
    }
}

// Docker Compose security checks
function checkDockerComposeSecurity(doc) {
    if (doc.version && doc.services) {
        const lineInfo = findLineInfo(doc, 'version');
        
        Object.keys(doc.services).forEach(serviceName => {
            const service = doc.services[serviceName];
            
            // Check for privileged mode in Docker Compose
            if (service.privileged) {
                addFinding('Docker-Privileged', `Docker service '${serviceName}' runs in privileged mode`, 
                          serviceName, 'Docker Service', 'High', lineInfo,
                          'Remove privileged: true from Docker Compose configuration');
            }
            
            // Check for host network mode
            if (service.network_mode === 'host') {
                addFinding('Docker-HostNetwork', `Docker service '${serviceName}' uses host network`, 
                          serviceName, 'Docker Service', 'High', lineInfo,
                          'Use bridge network instead of host network');
            }
            
            // Check for volume mounts
            if (service.volumes) {
                service.volumes.forEach(volume => {
                    if (typeof volume === 'string' && volume.includes('/:')) {
                        addFinding('Docker-HostMount', `Docker service '${serviceName}' mounts host directory`, 
                                  serviceName, 'Docker Service', 'High', lineInfo,
                                  'Avoid mounting host directories, use named volumes');
                    }
                });
            }
        });
    }
}

// ============================================
// COMPREHENSIVE SECURITY CHECK FUNCTIONS
// ============================================

function checkPodSecurity(pod) {
    const spec = pod.spec || {};
    const resourceName = pod.metadata?.name || 'Unknown';
    const podLineInfo = findLineInfo(pod, 'kind', 'Pod');

    console.log(`Checking pod security for: ${resourceName}`);

    // Advanced host namespace checks
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

    // Service account with auto-fix
    if (!spec.serviceAccountName || spec.serviceAccountName === 'default') {
        addFinding('defaultServiceAccount', `Pod uses default service account`, resourceName, pod.kind, 'Medium', podLineInfo);
        addAutoFix(pod, 'spec.serviceAccountName', `${resourceName}-sa`);
    }

    // Automount service account token
    if (spec.automountServiceAccountToken !== false) {
        addFinding('defaultServiceAccount', `Pod automatically mounts service account token`, resourceName, pod.kind, 'Medium', podLineInfo);
        addAutoFix(pod, 'spec.automountServiceAccountToken', false);
    }

    // Check all containers (including init containers)
    const containers = [...(spec.containers || []), ...(spec.initContainers || [])];
    containers.forEach((container, index) => {
        const isInit = index >= (spec.containers?.length || 0);
        const containerLineInfo = findLineInfo(isInit ? spec.initContainers : spec.containers, index, container.name);
        checkContainerSecurity(container, resourceName, pod.kind, containerLineInfo, isInit);
    });

    // Advanced volume checks
    if (spec.volumes) {
        spec.volumes.forEach((vol, index) => {
            const volLineInfo = findLineInfo(spec.volumes, index, vol.name);
            checkVolumeSecurity(vol, resourceName, pod.kind, volLineInfo);
        });
    }

    // Pod security context with auto-fixes
    if (spec.securityContext) {
        const secCtxLineInfo = findLineInfo(spec, 'securityContext');
        if (spec.securityContext.runAsNonRoot !== true) {
            addFinding('runAsRoot', `Pod does not enforce runAsNonRoot`, resourceName, pod.kind, 'High', secCtxLineInfo);
            addAutoFix(pod, 'spec.securityContext.runAsNonRoot', true);
        }
        if (!spec.securityContext.seccompProfile || spec.securityContext.seccompProfile.type !== 'RuntimeDefault') {
            addFinding('seccomp', `Pod missing default seccomp profile`, resourceName, pod.kind, 'Medium', secCtxLineInfo);
            addAutoFix(pod, 'spec.securityContext.seccompProfile', { type: 'RuntimeDefault' });
        }
        if (spec.securityContext.runAsUser === 0) {
            addFinding('pod-runAsRoot', `Pod security context runs as root`, resourceName, pod.kind, 'High', secCtxLineInfo);
            addAutoFix(pod, 'spec.securityContext.runAsUser', 1000);
        }
    } else {
        const specLineInfo = findLineInfo(pod, 'spec');
        addFinding('security-context', `Pod missing security context`, resourceName, pod.kind, 'Medium', specLineInfo);
        addAutoFix(pod, 'spec.securityContext', {
            runAsNonRoot: true,
            runAsUser: 1000,
            runAsGroup: 3000,
            seccompProfile: { type: 'RuntimeDefault' }
        });
    }

    // Node selector/affinity/tolerations security
    checkNodeSecurity(spec, resourceName, pod.kind, podLineInfo);
    
    // Priority class checks
    if (spec.priorityClassName) {
        addFinding('priority-class', `Pod uses priority class: ${spec.priorityClassName}`, resourceName, pod.kind, 'Info', podLineInfo);
    }

    // Topology spread constraints
    if (spec.topologySpreadConstraints) {
        addFinding('topology-spread', `Pod uses topology spread constraints`, resourceName, pod.kind, 'Info', podLineInfo);
    }
}

function checkContainerSecurity(container, resourceName, kind, lineInfo, isInitContainer = false) {
    const ctx = container.securityContext || {};
    const name = container.name;
    const containerType = isInitContainer ? 'Init Container' : 'Container';

    console.log(`Checking ${containerType.toLowerCase()}: ${name}`);

    // Advanced privileged check
    if (ctx.privileged) {
        addFinding('privileged', `${containerType} '${name}' runs in privileged mode`, resourceName, kind, 'High', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.privileged', false);
    }

    // Privilege escalation with auto-fix
    if (ctx.allowPrivilegeEscalation !== false) {
        const severity = ctx.allowPrivilegeEscalation ? 'High' : 'Medium';
        addFinding('allowPrivilegeEscalation', `${containerType} '${name}' allows privilege escalation`, 
                  resourceName, kind, severity, lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.allowPrivilegeEscalation', false);
    }

    // Root user check with auto-fix
    if (ctx.runAsUser === 0 || ctx.runAsUser === '0') {
        addFinding('runAsRoot', `${containerType} '${name}' runs as root user (UID 0)`, 
                  resourceName, kind, 'High', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.runAsUser', 1000);
    }

    // Read-only root filesystem
    if (ctx.readOnlyRootFilesystem !== true) {
        addFinding('readOnlyRootFS', `${containerType} '${name}' does not have read-only root filesystem`, 
                  resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.readOnlyRootFilesystem', true);
    }

    // Advanced capabilities management
    if (ctx.capabilities?.add) {
        const dangerous = ctx.capabilities.add.filter(cap => 
            DANGEROUS_CAPABILITIES.includes(cap.toUpperCase())
        );
        if (dangerous.length > 0) {
            addFinding('capabilities', `${containerType} '${name}' has dangerous capabilities: ${dangerous.join(', ')}`, 
                      resourceName, kind, 'High', lineInfo);
            addAutoFixForContainer(resourceName, kind, container, 'securityContext.capabilities.add', 
                ctx.capabilities.add.filter(cap => !DANGEROUS_CAPABILITIES.includes(cap.toUpperCase()))
            );
        }
    }
    
    // Ensure ALL capabilities are dropped
    if (!ctx.capabilities?.drop?.includes('ALL')) {
        addFinding('capabilities', `${containerType} '${name}' does not drop all capabilities`, 
                  resourceName, kind, 'Medium', lineInfo);
        const newDrop = ctx.capabilities?.drop || [];
        if (!newDrop.includes('ALL')) newDrop.push('ALL');
        addAutoFixForContainer(resourceName, kind, container, 'securityContext.capabilities.drop', newDrop);
    }

    // Advanced resource management
    if (!container.resources?.limits) {
        addFinding('resourceLimits', `${containerType} '${name}' has no resource limits`, 
                  resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'resources.limits', {
            cpu: '500m',
            memory: '512Mi'
        });
    } else {
        if (!container.resources.limits.cpu) {
            addFinding('resourceLimitsCPU', `${containerType} '${name}' has no CPU limit`, 
                      resourceName, kind, 'Medium', lineInfo);
            addAutoFixForContainer(resourceName, kind, container, 'resources.limits.cpu', '500m');
        }
        if (!container.resources.limits.memory) {
            addFinding('resourceLimitsMemory', `${containerType} '${name}' has no memory limit`, 
                      resourceName, kind, 'Medium', lineInfo);
            addAutoFixForContainer(resourceName, kind, container, 'resources.limits.memory', '512Mi');
        }
    }
    
    if (!container.resources?.requests) {
        addFinding('resource-requests', `${containerType} '${name}' has no resource requests`, 
                  resourceName, kind, 'Low', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'resources.requests', {
            cpu: '100m',
            memory: '128Mi'
        });
    }

    // Health probes with auto-fixes
    if (!container.livenessProbe) {
        addFinding('missingProbes', `${containerType} '${name}' missing liveness probe`, 
                  resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'livenessProbe', {
            httpGet: { path: '/healthz', port: 8080 },
            initialDelaySeconds: 15,
            periodSeconds: 10,
            timeoutSeconds: 5,
            successThreshold: 1,
            failureThreshold: 3
        });
    }
    if (!container.readinessProbe) {
        addFinding('missingProbes', `${containerType} '${name}' missing readiness probe`, 
                  resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'readinessProbe', {
            httpGet: { path: '/ready', port: 8080 },
            initialDelaySeconds: 5,
            periodSeconds: 5,
            timeoutSeconds: 3,
            successThreshold: 1,
            failureThreshold: 3
        });
    }

    // Image security
    if (container.image) {
        if (container.image.endsWith(':latest') || !container.image.includes(':')) {
            addFinding('imageLatestTag', `${containerType} '${name}' uses 'latest' or no tag`, 
                      resourceName, kind, 'Medium', lineInfo);
        }
        if (!container.image.includes('@sha256:')) {
            addFinding('imageDigest', `${containerType} '${name}' not using immutable image digest`, 
                      resourceName, kind, 'Low', lineInfo);
        }
        if (container.imagePullPolicy === 'Always') {
            addFinding('image-pull-policy', `${containerType} '${name}' uses Always pull policy`, 
                      resourceName, kind, 'Low', lineInfo);
        }
    }

    // Advanced environment variable checks
    if (container.env) {
        container.env.forEach((envVar, index) => {
            const envLineInfo = findLineInfo(container.env, index, envVar.name);
            if (envVar.valueFrom?.secretKeyRef) {
                addFinding('secretsEnv', `${containerType} '${name}' uses secret in env var '${envVar.name}'`, 
                          resourceName, kind, 'Medium', envLineInfo);
            }
            if (envVar.value && SECRET_PATTERNS.some(p => p.regex.test(envVar.value))) {
                addFinding('hardcoded-env', `${containerType} '${name}' has hardcoded secret in env var '${envVar.name}'`, 
                          resourceName, kind, 'Critical', envLineInfo);
            }
        });
    }

    // Ports and networking
    if (container.ports) {
        container.ports.forEach((port, index) => {
            const portLineInfo = findLineInfo(container.ports, index, port.containerPort);
            if (port.hostPort) {
                addFinding('hostPort', `${containerType} '${name}' uses hostPort: ${port.hostPort}`, 
                          resourceName, kind, 'Medium', portLineInfo);
            }
            if (!port.protocol) {
                addFinding('port-protocol', `${containerType} '${name}' port ${port.containerPort} missing protocol`, 
                          resourceName, kind, 'Low', portLineInfo);
            }
        });
    }

    // Command and args security
    if (container.command && container.command.includes('sh') && container.command.includes('-c')) {
        addFinding('shell-command', `${containerType} '${name}' uses shell command execution`, 
                  resourceName, kind, 'Low', lineInfo);
    }

    // Security context missing
    if (!container.securityContext) {
        addFinding('container-security-context', `${containerType} '${name}' missing security context`, 
                  resourceName, kind, 'Medium', lineInfo);
        addAutoFixForContainer(resourceName, kind, container, 'securityContext', {
            runAsUser: 1000,
            runAsGroup: 3000,
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: {
                drop: ['ALL']
            }
        });
    }
}

function checkVolumeSecurity(vol, resourceName, kind, lineInfo) {
    if (vol.hostPath) {
        addFinding('hostPathVolume', `Volume '${vol.name}' uses hostPath: ${vol.hostPath.path}`, 
                  resourceName, kind, 'High', lineInfo);
    }
    
    if (vol.emptyDir && vol.emptyDir.medium === 'Memory') {
        addFinding('memory-volume', `Volume '${vol.name}' uses memory-backed emptyDir`, 
                  resourceName, kind, 'Medium', lineInfo);
    }
    
    if (vol.configMap && vol.configMap.defaultMode !== 0o644) {
        addFinding('configmap-permissions', `Volume '${vol.name}' configMap has non-standard permissions`, 
                  resourceName, kind, 'Low', lineInfo);
    }
}

// [Rest of the functions continue with similar comprehensive coverage...]

// Due to character limits, I'll provide the rest of the functions in the next message
// This includes: checkWorkloadSecurity, checkNodeSecurity, checkServiceSecurity, 
// checkIngressSecurity, checkNetworkPolicy, checkRBAC, checkSecretSecurity, 
// checkConfigMapSecurity, checkServiceAccountSecurity, checkStorageSecurity, 
// checkHPASecurity, checkDeprecatedAPIs, checkBetaFeatures, checkPodSecurityStandards,
// checkContainerRuntimeSecurity, checkCloudProviderSecurity, checkGenericSecurity,
// scanSecrets, findLineInfo, addFinding, addAutoFix, addAutoFixForContainer,
// getRemediation, renderResults, renderFindingsTable, renderFixes, filterFindings,
// exportPDF, exportExcel, exportJSON, downloadFixes, and other helper functions

// Let me know if you want me to continue with the complete implementation!

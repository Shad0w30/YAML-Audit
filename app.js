// ============================================
// ADVANCED KUBERNETES SECURITY SCANNER
// ============================================

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

// Global state
let findings = [];
let currentFilter = 'all';
let originalConfig = '';
let configLines = [];

// ============================================
// INITIALIZATION - Run when page loads
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('Security Scanner initialized');
    
    // Set up event listeners
    document.getElementById('scan-btn').addEventListener('click', scanConfiguration);
    document.getElementById('load-sample-btn').addEventListener('click', loadSample);
    document.getElementById('clear-btn').addEventListener('click', clearInput);
    document.getElementById('export-pdf-btn').addEventListener('click', exportPDF);
    document.getElementById('export-excel-btn').addEventListener('click', exportExcel);
    document.getElementById('export-json-btn').addEventListener('click', exportJSON);
    document.getElementById('download-fixes-btn').addEventListener('click', downloadFixes);
    
    // Initialize the first tab as active
    switchTab(null, 'input');
});

// ============================================
// UI FUNCTIONS
// ============================================

// Tab switching
function switchTab(event, tab) {
    if (event) {
        event.preventDefault();
    }
    
    console.log(`Switching to tab: ${tab}`);
    
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
    
    // Add active class to clicked tab button (if event exists)
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        // Find and activate the correct tab button
        tabButtons.forEach(btn => {
            if (btn.textContent.includes(tab.charAt(0).toUpperCase() + tab.slice(1))) {
                btn.classList.add('active');
            }
        });
    }
    
    // Show the selected tab content
    const tabElement = document.getElementById(`${tab}-tab`);
    if (tabElement) {
        tabElement.classList.add('active');
    }
}

// Load sample configuration
function loadSample() {
    console.log('Loading sample configuration...');
    
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
    showNotification('Sample configuration loaded successfully!', 'success');
}

// Clear input
function clearInput() {
    console.log('Clearing input...');
    document.getElementById('config-input').value = '';
    showNotification('Input cleared', 'info');
}

// Show notification
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notification => {
        notification.remove();
    });
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 8px;
        color: white;
        font-weight: 600;
        z-index: 1000;
        animation: slideIn 0.3s ease;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    
    // Set background color based on type
    if (type === 'success') {
        notification.style.backgroundColor = '#28a745';
    } else if (type === 'error') {
        notification.style.backgroundColor = '#dc3545';
    } else {
        notification.style.backgroundColor = '#17a2b8';
    }
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

// Add CSS for animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// ============================================
// MAIN SCANNING FUNCTION
// ============================================

function scanConfiguration() {
    console.log('Starting security scan...');
    
    const input = document.getElementById('config-input').value.trim();
    
    if (!input) {
        showNotification('Please enter some configuration to scan', 'error');
        return;
    }

    // Show loading state
    const scanButton = document.getElementById('scan-btn');
    const originalText = scanButton.innerHTML;
    scanButton.innerHTML = '<span class="loading-spinner"></span> Scanning...';
    scanButton.disabled = true;

    // Reset state
    findings = [];
    originalConfig = input;
    configLines = input.split('\n');

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
            
            // Scan the document
            scanDocument(doc);
            
            // Scan for secrets
            scanSecrets(doc);
        });

        console.log(`Scan complete. Found ${findings.length} security issues`);
        
        // Render results
        renderResults();
        renderFixes();
        
        // Switch to results tab
        switchTab(null, 'results');
        
        showNotification(`Scan complete! Found ${findings.length} security issues.`, 'success');
        
    } catch (error) {
        console.error('Scan error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        // Reset button state
        scanButton.innerHTML = originalText;
        scanButton.disabled = false;
    }
}

// ============================================
// SECURITY CHECK FUNCTIONS
// ============================================

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
            checkRBAC(doc);
            break;
        case 'secret':
            checkSecret(doc);
            break;
        case 'configmap':
            checkConfigMap(doc);
            break;
    }
}

function checkPodSecurity(pod) {
    const spec = pod.spec || {};
    const resourceName = pod.metadata?.name || 'Unknown';

    console.log(`Checking pod security for: ${resourceName}`);

    // Host namespaces
    if (spec.hostNetwork) {
        addFinding('hostNamespace', `Pod shares host network namespace`, resourceName, pod.kind);
    }
    if (spec.hostPID) {
        addFinding('hostNamespace', `Pod shares host PID namespace`, resourceName, pod.kind);
    }
    if (spec.hostIPC) {
        addFinding('hostNamespace', `Pod shares host IPC namespace`, resourceName, pod.kind);
    }

    // Service account
    if (!spec.serviceAccountName || spec.serviceAccountName === 'default') {
        addFinding('defaultServiceAccount', `Pod uses default service account`, resourceName, pod.kind);
    }

    // Containers
    const containers = [...(spec.containers || []), ...(spec.initContainers || [])];
    containers.forEach(container => checkContainerSecurity(container, resourceName, pod.kind));

    // Volumes
    if (spec.volumes) {
        spec.volumes.forEach(vol => {
            if (vol.hostPath) {
                addFinding('hostPathVolume', `Pod uses hostPath volume: ${vol.name}`, resourceName, pod.kind);
            }
        });
    }

    // Security context
    if (spec.securityContext) {
        if (!spec.securityContext.runAsNonRoot) {
            addFinding('runAsRoot', `Pod does not enforce runAsNonRoot`, resourceName, pod.kind);
        }
        if (!spec.securityContext.seccompProfile || spec.securityContext.seccompProfile.type !== 'RuntimeDefault') {
            addFinding('seccomp', `Pod missing seccomp profile`, resourceName, pod.kind);
        }
    }
}

function checkWorkloadSecurity(workload) {
    const template = workload.spec?.template;
    if (template) {
        checkPodSecurity({
            kind: 'Pod',
            metadata: { name: workload.metadata?.name },
            spec: template.spec
        });
    }
}

function checkContainerSecurity(container, resourceName, kind) {
    const ctx = container.securityContext || {};
    const name = container.name;

    console.log(`Checking container: ${name}`);

    // Privileged
    if (ctx.privileged) {
        addFinding('privileged', `Container '${name}' runs in privileged mode`, resourceName, kind);
    }

    // Privilege escalation
    if (ctx.allowPrivilegeEscalation !== false) {
        addFinding('allowPrivilegeEscalation', `Container '${name}' allows privilege escalation`, resourceName, kind);
    }

    // Root user
    if (ctx.runAsUser === 0) {
        addFinding('runAsRoot', `Container '${name}' runs as root (UID 0)`, resourceName, kind);
    }

    // Read-only root filesystem
    if (!ctx.readOnlyRootFilesystem) {
        addFinding('readOnlyRootFS', `Container '${name}' has writable root filesystem`, resourceName, kind);
    }

    // Capabilities
    if (ctx.capabilities?.add) {
        const dangerous = ctx.capabilities.add.filter(cap => 
            DANGEROUS_CAPABILITIES.includes(cap.toUpperCase())
        );
        if (dangerous.length > 0) {
            addFinding('capabilities', `Container '${name}' has dangerous capabilities: ${dangerous.join(', ')}`, resourceName, kind);
        }
    }

    // Resource limits
    if (!container.resources?.limits) {
        addFinding('resourceLimits', `Container '${name}' has no resource limits`, resourceName, kind);
    }

    // Health probes
    if (!container.livenessProbe || !container.readinessProbe) {
        addFinding('missingProbes', `Container '${name}' missing health probes`, resourceName, kind);
    }

    // Image tag
    if (container.image && (container.image.endsWith(':latest') || !container.image.includes(':'))) {
        addFinding('imageLatestTag', `Container '${name}' uses 'latest' or no tag`, resourceName, kind);
    }

    // Environment variables
    if (container.env) {
        container.env.forEach(envVar => {
            if (envVar.valueFrom?.secretKeyRef) {
                addFinding('secretsEnv', `Container '${name}' uses secret in env var '${envVar.name}'`, resourceName, kind);
            }
        });
    }
}

function checkServiceSecurity(svc) {
    const resourceName = svc.metadata?.name || 'Unknown';
    console.log(`Checking service: ${resourceName}`);
    
    if (svc.spec?.type === 'LoadBalancer') {
        addFinding('Service-LoadBalancer', `Service exposes LoadBalancer publicly`, resourceName, svc.kind, 'Medium');
    }
    
    if (svc.spec?.externalIPs?.length > 0) {
        addFinding('Service-ExternalIP', `Service uses external IPs`, resourceName, svc.kind, 'High');
    }
}

function checkIngressSecurity(ingress) {
    const resourceName = ingress.metadata?.name || 'Unknown';
    console.log(`Checking ingress: ${resourceName}`);
    
    if (!ingress.spec?.tls || ingress.spec.tls.length === 0) {
        addFinding('Ingress-NoTLS', `Ingress does not enforce TLS`, resourceName, ingress.kind, 'High');
    }
}

function checkNetworkPolicy(policy) {
    const resourceName = policy.metadata?.name || 'Unknown';
    console.log(`Checking network policy: ${resourceName}`);
    
    if (!policy.spec?.ingress) {
        addFinding('networkPolicy', `NetworkPolicy has no ingress rules`, resourceName, policy.kind);
    }
    
    if (!policy.spec?.egress) {
        addFinding('networkPolicy', `NetworkPolicy has no egress rules`, resourceName, policy.kind);
    }
}

function checkRBAC(role) {
    const resourceName = role.metadata?.name || 'Unknown';
    console.log(`Checking RBAC: ${resourceName}`);
    
    if (role.rules) {
        role.rules.forEach(rule => {
            if (rule.resources?.includes('*')) {
                addFinding('RBAC-Wildcard', `${role.kind} allows wildcard resources`, resourceName, role.kind, 'High');
            }
            if (rule.verbs?.includes('*')) {
                addFinding('RBAC-Wildcard', `${role.kind} allows wildcard verbs`, resourceName, role.kind, 'High');
            }
        });
    }
}

function checkSecret(secret) {
    const resourceName = secret.metadata?.name || 'Unknown';
    console.log(`Checking secret: ${resourceName}`);
    
    if (secret.data) {
        Object.keys(secret.data).forEach(key => {
            try {
                const decoded = atob(secret.data[key]);
                SECRET_PATTERNS.forEach(pattern => {
                    if (pattern.regex.test(decoded)) {
                        addFinding('Secret-Exposed', `Secret contains ${pattern.desc} in key '${key}'`, resourceName, secret.kind, 'Critical');
                    }
                });
            } catch (e) {
                // Invalid base64
            }
        });
    }
}

function checkConfigMap(configMap) {
    const resourceName = configMap.metadata?.name || 'Unknown';
    console.log(`Checking configmap: ${resourceName}`);
    
    if (configMap.data) {
        Object.values(configMap.data).forEach(value => {
            SECRET_PATTERNS.forEach(pattern => {
                if (pattern.regex.test(value)) {
                    addFinding('ConfigMap-Secret', `ConfigMap contains ${pattern.desc}`, resourceName, configMap.kind, 'High');
                }
            });
        });
    }
}

function scanSecrets(doc) {
    const docString = JSON.stringify(doc);
    const resourceName = doc.metadata?.name || 'Unknown';
    
    SECRET_PATTERNS.forEach(pattern => {
        const matches = docString.match(new RegExp(pattern.regex, 'g'));
        if (matches) {
            matches.slice(0, 3).forEach(match => {
                addFinding('Hardcoded-Secret', `${pattern.desc}: ${match.substring(0, 20)}...`, resourceName, doc.kind || 'Unknown', pattern.severity);
            });
        }
    });
}

// ============================================
// HELPER FUNCTIONS
// ============================================

function addFinding(type, message, resource, kind, customSeverity = null) {
    const benchmark = CIS_BENCHMARKS[type];
    const id = benchmark?.id || type;
    const title = benchmark?.title || type;
    const severity = customSeverity || benchmark?.severity || 'Medium';
    
    console.log(`Finding: [${severity}] ${title} - ${message}`);
    
    findings.push({
        id,
        title,
        message,
        severity,
        resource,
        kind,
        remediation: getRemediation(type)
    });
}

function getRemediation(type) {
    const remediations = {
        privileged: 'Set securityContext.privileged to false',
        allowPrivilegeEscalation: 'Set securityContext.allowPrivilegeEscalation to false',
        runAsRoot: 'Set securityContext.runAsUser to non-zero and runAsNonRoot to true',
        readOnlyRootFS: 'Set securityContext.readOnlyRootFilesystem to true',
        capabilities: 'Remove dangerous capabilities and drop all with securityContext.capabilities.drop: ["ALL"]',
        resourceLimits: 'Define resources.limits for CPU and memory',
        imageLatestTag: 'Use specific immutable image tags',
        hostNamespace: 'Set hostNetwork, hostPID, and hostIPC to false',
        defaultServiceAccount: 'Create and use a dedicated ServiceAccount',
        hostPathVolume: 'Avoid hostPath volumes, use PersistentVolumes instead',
        missingProbes: 'Add livenessProbe and readinessProbe',
        networkPolicy: 'Define NetworkPolicy with specific ingress/egress rules',
        secretsEnv: 'Mount secrets as volumes instead of environment variables',
        seccomp: 'Set securityContext.seccompProfile.type to RuntimeDefault',
        appArmor: 'Add AppArmor annotations',
        'Service-LoadBalancer': 'Consider using ClusterIP or NodePort instead',
        'Service-ExternalIP': 'Remove externalIPs configuration',
        'Ingress-NoTLS': 'Configure TLS certificates for HTTPS',
        'RBAC-Wildcard': 'Specify exact resources and verbs needed',
        'Secret-Exposed': 'Remove sensitive data from secrets, use external secret management',
        'ConfigMap-Secret': 'Move sensitive data to Kubernetes Secrets',
        'Hardcoded-Secret': 'Remove hardcoded secrets, use Kubernetes Secrets or external vaults'
    };
    return remediations[type] || 'Review and fix the security issue';
}

// ============================================
// RENDERING FUNCTIONS
// ============================================

function renderResults() {
    const summarySection = document.getElementById('summary-section');
    const resultsSection = document.getElementById('results-section');
    const filterBar = document.getElementById('filter-bar');
    const exportControls = document.getElementById('export-controls');
    
    console.log(`Rendering ${findings.length} findings`);
    
    if (findings.length === 0) {
        summarySection.innerHTML = '';
        resultsSection.innerHTML = `
            <div class="no-findings">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <h2>No Security Issues Found!</h2>
                <p>Your configuration appears to be secure.</p>
            </div>
        `;
        filterBar.style.display = 'none';
        exportControls.style.display = 'none';
        return;
    }

    // Count findings by severity
    const counts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Info: 0
    };

    findings.forEach(f => counts[f.severity]++);

    // Render summary section
    summarySection.innerHTML = `
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="summary-count">${counts.Critical}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-count">${counts.High}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-count">${counts.Medium}</div>
                <div class="summary-label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="summary-count">${counts.Low}</div>
                <div class="summary-label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="summary-count">${counts.Info}</div>
                <div class="summary-label">Info</div>
            </div>
        </div>
    `;

    // Render findings table
    renderFindingsTable();
    
    // Show filter bar and export controls
    filterBar.style.display = 'flex';
    exportControls.style.display = 'flex';
}

function renderFindingsTable() {
    const resultsSection = document.getElementById('results-section');
    const filtered = currentFilter === 'all' 
        ? findings 
        : findings.filter(f => f.severity === currentFilter);

    console.log(`Rendering ${filtered.length} filtered findings (filter: ${currentFilter})`);

    if (filtered.length === 0) {
        resultsSection.innerHTML = '<div class="no-findings"><p>No findings for selected filter.</p></div>';
        return;
    }

    let tableHTML = `
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Resource</th>
                    <th>Kind</th>
                    <th>Message</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
    `;

    filtered.forEach(finding => {
        tableHTML += `
            <tr>
                <td><span class="severity-badge severity-${finding.severity.toLowerCase()}">${finding.severity}</span></td>
                <td><code>${finding.id}</code></td>
                <td>${finding.title}</td>
                <td>${finding.resource}</td>
                <td>${finding.kind}</td>
                <td>${finding.message}</td>
                <td>${finding.remediation}</td>
            </tr>
        `;
    });

    tableHTML += '</tbody></table>';
    resultsSection.innerHTML = tableHTML;
}

function renderFixes() {
    const fixesSection = document.getElementById('fixes-section');
    const fixControls = document.getElementById('fix-controls');
    
    console.log('Rendering fixes');
    
    if (findings.length === 0) {
        fixesSection.innerHTML = '<div class="no-findings"><p>No fixes needed - configuration is secure!</p></div>';
        fixControls.style.display = 'none';
        return;
    }

    let fixHTML = '<div class="stats-bar"><strong>Auto-fix suggestions generated based on findings</strong></div>';
    
    // Group findings by resource type and name
    const groupedFindings = {};
    findings.forEach(f => {
        const key = `${f.kind}:${f.resource}`;
        if (!groupedFindings[key]) {
            groupedFindings[key] = [];
        }
        groupedFindings[key].push(f);
    });

    Object.keys(groupedFindings).forEach(key => {
        const [kind, resource] = key.split(':');
        fixHTML += `
            <div class="fix-item">
                <h4>${kind}: ${resource}</h4>
                <ul>
        `;
        
        groupedFindings[key].forEach(f => {
            fixHTML += `<li><strong>${f.title}:</strong> ${f.remediation}</li>`;
        });
        
        fixHTML += '</ul></div>';
    });

    fixesSection.innerHTML = fixHTML;
    fixControls.style.display = 'flex';
}

// ============================================
// FILTER AND EXPORT FUNCTIONS
// ============================================

function filterFindings(severity) {
    currentFilter = severity;
    console.log(`Filtering by: ${severity}`);
    
    // Update active filter button
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    // Re-render the findings table
    renderFindingsTable();
}

function exportPDF() {
    console.log('Generating PDF report...');
    
    if (findings.length === 0) {
        showNotification('No findings to export', 'error');
        return;
    }
    
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF('p', 'mm', 'a4');
        
        // Get counts
        const counts = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0,
            Info: 0
        };
        findings.forEach(f => counts[f.severity]++);
        
        // Title
        doc.setFontSize(24);
        doc.setTextColor(102, 126, 234);
        doc.text('Security Scan Report', 105, 20, { align: 'center' });
        
        doc.setFontSize(12);
        doc.setTextColor(108, 117, 125);
        doc.text('Kubernetes & Docker Configuration Analysis', 105, 28, { align: 'center' });
        doc.text(`Generated: ${new Date().toLocaleString()}`, 105, 34, { align: 'center' });
        
        // Line separator
        doc.setDrawColor(102, 126, 234);
        doc.setLineWidth(0.5);
        doc.line(20, 40, 190, 40);
        
        let yPos = 50;
        
        // Executive Summary
        doc.setFontSize(16);
        doc.setTextColor(73, 80, 87);
        doc.text('Executive Summary', 20, yPos);
        yPos += 10;
        
        doc.setFontSize(10);
        doc.setTextColor(108, 117, 125);
        doc.text(`Total Findings: ${findings.length}`, 20, yPos);
        yPos += 6;
        doc.text(`Critical: ${counts.Critical}  |  High: ${counts.High}  |  Medium: ${counts.Medium}  |  Low: ${counts.Low}  |  Info: ${counts.Info}`, 20, yPos);
        yPos += 10;
        
        // Risk Assessment
        const riskLevel = counts.Critical > 0 ? 'CRITICAL' : 
                         counts.High > 0 ? 'HIGH' : 
                         counts.Medium > 0 ? 'MEDIUM' : 'LOW';
        
        doc.setFontSize(11);
        doc.text(`Overall Risk Level: ${riskLevel}`, 20, yPos);
        yPos += 10;
        
        // Detailed Findings
        doc.setFontSize(16);
        doc.setTextColor(73, 80, 87);
        doc.text('Detailed Findings', 20, yPos);
        yPos += 8;
        
        const severities = ['Critical', 'High', 'Medium', 'Low', 'Info'];
        
        severities.forEach(severity => {
            const severityFindings = findings.filter(f => f.severity === severity);
            if (severityFindings.length === 0) return;
            
            // Check if we need a new page
            if (yPos > 250) {
                doc.addPage();
                yPos = 20;
            }
            
            doc.setFontSize(12);
            doc.setTextColor(73, 80, 87);
            doc.text(`${severity} Severity (${severityFindings.length})`, 20, yPos);
            yPos += 6;
            
            doc.setFontSize(9);
            doc.setTextColor(108, 117, 125);
            
            severityFindings.forEach((finding, index) => {
                if (yPos > 270) {
                    doc.addPage();
                    yPos = 20;
                }
                
                const text = `${index + 1}. [${finding.id}] ${finding.title}`;
                doc.text(text, 25, yPos);
                yPos += 5;
                
                const resourceText = `   Resource: ${finding.resource} (${finding.kind})`;
                doc.text(resourceText, 25, yPos);
                yPos += 4;
                
                const messageLines = doc.splitTextToSize(`   ${finding.message}`, 160);
                doc.text(messageLines, 25, yPos);
                yPos += messageLines.length * 4;
                
                const remediationLines = doc.splitTextToSize(`   Fix: ${finding.remediation}`, 160);
                doc.setTextColor(40, 167, 69);
                doc.text(remediationLines, 25, yPos);
                doc.setTextColor(108, 117, 125);
                yPos += remediationLines.length * 4 + 3;
            });
            
            yPos += 5;
        });
        
        // Add footer with page numbers
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.setTextColor(150);
            doc.text(`Page ${i} of ${pageCount}`, 105, 290, { align: 'center' });
            doc.text('Generated by K8s & Docker Security Scanner', 105, 295, { align: 'center' });
        }
        
        // Save the PDF
        doc.save('security-scan-report.pdf');
        showNotification('PDF report generated successfully!', 'success');
        
    } catch (error) {
        console.error('Error generating PDF:', error);
        showNotification('Error generating PDF report: ' + error.message, 'error');
    }
}

function exportExcel() {
    console.log('Exporting to Excel...');
    
    if (findings.length === 0) {
        showNotification('No findings to export', 'error');
        return;
    }
    
    try {
        // Prepare data
        const data = findings.map(f => ({
            'Severity': f.severity,
            'ID': f.id,
            'Title': f.title,
            'Resource': f.resource,
            'Kind': f.kind,
            'Message': f.message,
            'Remediation': f.remediation
        }));
        
        // Create worksheet
        const worksheet = XLSX.utils.json_to_sheet(data);
        
        // Create workbook
        const workbook = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Security Findings');
        
        // Auto-size columns
        const maxWidths = {};
        Object.keys(data[0]).forEach(key => {
            maxWidths[key] = Math.max(
                key.length,
                ...data.map(row => String(row[key]).length)
            );
        });
        
        worksheet['!cols'] = Object.keys(maxWidths).map(key => ({ wch: Math.min(maxWidths[key], 50) }));
        
        // Save file
        XLSX.writeFile(workbook, 'security-findings.xlsx');
        showNotification('Excel file exported successfully!', 'success');
        
    } catch (error) {
        console.error('Error exporting to Excel:', error);
        showNotification('Error exporting to Excel: ' + error.message, 'error');
    }
}

function exportJSON() {
    console.log('Exporting to JSON...');
    
    if (findings.length === 0) {
        showNotification('No findings to export', 'error');
        return;
    }
    
    try {
        const report = {
            metadata: {
                generatedAt: new Date().toISOString(),
                totalFindings: findings.length,
                scannerVersion: '1.0.0'
            },
            summary: {
                Critical: findings.filter(f => f.severity === 'Critical').length,
                High: findings.filter(f => f.severity === 'High').length,
                Medium: findings.filter(f => f.severity === 'Medium').length,
                Low: findings.filter(f => f.severity === 'Low').length,
                Info: findings.filter(f => f.severity === 'Info').length
            },
            findings: findings
        };
        
        const jsonStr = JSON.stringify(report, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = 'security-findings.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showNotification('JSON file exported successfully!', 'success');
        
    } catch (error) {
        console.error('Error exporting to JSON:', error);
        showNotification('Error exporting to JSON: ' + error.message, 'error');
    }
}

function downloadFixes() {
    console.log('Downloading fixes...');
    
    if (findings.length === 0) {
        showNotification('No fixes to download', 'error');
        return;
    }
    
    try {
        // Generate a summary of fixes
        let fixesContent = `# Security Fixes Summary\n`;
        fixesContent += `# Generated: ${new Date().toLocaleString()}\n`;
        fixesContent += `# Total Issues: ${findings.length}\n\n`;
        
        // Group findings by resource
        const groupedFindings = {};
        findings.forEach(f => {
            const key = `${f.kind}:${f.resource}`;
            if (!groupedFindings[key]) {
                groupedFindings[key] = [];
            }
            groupedFindings[key].push(f);
        });
        
        Object.keys(groupedFindings).forEach(key => {
            const [kind, resource] = key.split(':');
            fixesContent += `## ${kind}: ${resource}\n`;
            
            groupedFindings[key].forEach((f, index) => {
                fixesContent += `${index + 1}. ${f.title}\n`;
                fixesContent += `   Issue: ${f.message}\n`;
                fixesContent += `   Fix: ${f.remediation}\n\n`;
            });
        });
        
        // Create and download file
        const blob = new Blob([fixesContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = 'security-fixes.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        showNotification('Fixes downloaded successfully!', 'success');
        
    } catch (error) {
        console.error('Error downloading fixes:', error);
        showNotification('Error downloading fixes: ' + error.message, 'error');
    }
}

// ============================================
// INITIALIZATION COMPLETE
// ============================================

console.log('K8s & Docker Security Scanner loaded successfully!');

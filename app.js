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

// Pod security checks
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
}

// Container security checks
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

// Service security checks
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

// Ingress security checks
function checkIngressSecurity(ingress) {
    const resourceName = ingress.metadata?.name || 'Unknown';
    console.log(`Checking ingress: ${resourceName}`);
    
    if (!ingress.spec?.tls || ingress.spec.tls.length === 0) {
        addFinding('Ingress-NoTLS', `Ingress does not enforce TLS`, resourceName, ingress.kind, 'High');
    }
}

// Network policy checks
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

// RBAC checks
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

// Secret checks
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

// ConfigMap checks
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

// Secret pattern scanning
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

// Add finding to results
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

// Get remediation advice
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

// Render results
function renderResults() {
    const summarySection = document.getElementById('summary-section');
    const resultsSection = document.getElementById('results-section');
    
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
        document.getElementById('filter-bar').style.display = 'none';
        document.getElementById('export-controls').style.display = 'none';
        return;
    }

    const counts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Info: 0
    };

    findings.forEach(f => counts[f.severity]++);

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

    renderFindingsTable();
    document.getElementById('filter-bar').style.display = 'flex';
    document.getElementById('export-controls').style.display = 'flex';
}

// Render findings table
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

// Render fixes
function renderFixes() {
    const fixesSection = document.getElementById('fixes-section');
    
    console.log('Rendering fixes');
    
    if (findings.length === 0) {
        fixesSection.innerHTML = '<div class="no-findings"><p>No fixes needed - configuration is secure!</p></div>';
        document.getElementById('fix-controls').style.display = 'none';
        return;
    }

    let fixHTML = '<div class="stats-bar"><strong>Auto-fix suggestions generated based on findings</strong></div>';
    
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
    document.getElementById('fix-controls').style.display = 'flex';
}

// Filter findings
function filterFindings(severity) {
    currentFilter = severity;
    console.log(`Filtering by: ${severity}`);
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    renderFindingsTable();
}

// Export PDF
async function exportPDF() {
    console.log('Generating PDF report...');
    
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
        
        // Findings by Severity
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
            doc.

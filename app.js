const CIS_MAP = {
  privileged: 'CIS 5.2.1',
  allowPrivilegeEscalation: 'CIS 5.2.6',
  runAsRoot: 'CIS 5.2.5',
  imageLatestTag: 'CIS 5.4.1',
  resourceLimits: 'CIS 5.1.1',
  missingProbes: 'CIS 5.7.4',
  hostNamespace: 'CIS 5.2.2/5.2.3/5.2.4',
  defaultServiceAccount: 'CIS 5.1.5',
  networkPolicy: 'CIS 6.3.1',
  hostPathVolume: 'CIS 5.3.6'
};

const SECRET_PATTERNS = [
  { regex: /AKIA[0-9A-Z]{16}/, desc: 'Possible AWS Access Key' },
  { regex: /secret[_-]?key/i, desc: 'Potential secret key reference' },
  { regex: /BEGIN RSA PRIVATE KEY/, desc: 'Private Key Detected' }
];

let findings = [];
let autoFixes = [];

function scanYaml() {
  const yamlContent = document.getElementById('yamlInput').value;
  let docs;
  try {
    docs = jsyaml.loadAll(yamlContent);
  } catch (e) {
    alert('Invalid YAML');
    return;
  }

  findings = [];
  autoFixes = [];

  docs.forEach(doc => {
    if (!doc || typeof doc !== 'object') return;

    checkHostNamespaces(doc);
    checkServiceAccount(doc);
    checkNetworkPolicy(doc);

    if (doc.spec?.template?.spec?.containers) {
      doc.spec.template.spec.containers.forEach(container => {
        checkContainerSecurity(container, doc);
      });
    }

    if (doc.spec?.containers) {
      doc.spec.containers.forEach(container => {
        checkContainerSecurity(container, doc);
      });
    }

    scanSecrets(doc);
  });

  renderResults();
}

function checkContainerSecurity(container, doc) {
  if (container.securityContext?.privileged) {
    findings.push({ id: CIS_MAP.privileged, msg: `Privileged container ${container.name}`, severity: 'High' });
    let patch = JSON.parse(JSON.stringify(doc));
    patch.spec.template?.spec?.containers.forEach(c => c.securityContext.privileged = false);
    autoFixes.push(patch);
  }
  if (container.securityContext?.allowPrivilegeEscalation) {
    findings.push({ id: CIS_MAP.allowPrivilegeEscalation, msg: `AllowPrivilegeEscalation enabled in ${container.name}`, severity: 'High' });
  }
  if (container.securityContext?.runAsUser === 0) {
    findings.push({ id: CIS_MAP.runAsRoot, msg: `Container ${container.name} running as root`, severity: 'High' });
  }
  if (!container.resources || Object.keys(container.resources).length === 0) {
    findings.push({ id: CIS_MAP.resourceLimits, msg: `Container ${container.name} has no resource limits/requests`, severity: 'Medium' });
  }
  if (!container.livenessProbe || !container.readinessProbe) {
    findings.push({ id: CIS_MAP.missingProbes, msg: `Container ${container.name} missing liveness/readiness probes`, severity: 'Medium' });
  }
  if (container.image && container.image.endsWith(':latest')) {
    findings.push({ id: CIS_MAP.imageLatestTag, msg: `Container ${container.name} uses latest tag`, severity: 'Medium' });
  }
  if (container.volumeMounts) {
    container.volumeMounts.forEach(vm => {
      const vol = doc.spec?.volumes?.find(v => v.name === vm.name);
      if (vol?.hostPath) {
        findings.push({ id: CIS_MAP.hostPathVolume, msg: `HostPath volume mounted in ${container.name} at ${vm.mountPath}`, severity: 'High' });
      }
    });
  }
}

function checkHostNamespaces(doc) {
  ['hostNetwork','hostPID','hostIPC'].forEach(ns => {
    if (doc.spec?.[ns]) {
      findings.push({ id: CIS_MAP.hostNamespace, msg: `${ns} enabled`, severity: 'High' });
    }
  });
}

function checkServiceAccount(doc) {
  if (doc.spec?.serviceAccountName === 'default' && doc.spec?.automountServiceAccountToken) {
    findings.push({ id: CIS_MAP.defaultServiceAccount, msg: 'Default service account with token automount', severity: 'High' });
  }
}

function checkNetworkPolicy(doc) {
  if (doc.kind === 'NetworkPolicy') {
    if (!doc.spec?.ingress?.length || !doc.spec?.egress?.length) {
      findings.push({ id: CIS_MAP.networkPolicy, msg: 'Overly permissive NetworkPolicy detected', severity: 'High' });
    }
  }
}

function scanSecrets(doc) {
  const docString = JSON.stringify(doc);
  SECRET_PATTERNS.forEach(p => {
    if (p.regex.test(docString)) {
      findings.push({ id: 'Secrets', msg: p.desc, severity: 'Critical' });
    }
  });
}

function renderResults() {
  const resultsDiv = document.getElementById('results');
  resultsDiv.innerHTML = '<h2>Findings</h2>' + findings.map(f => `<div class="finding"><b>${f.id}</b>: ${f.msg} — <i>${f.severity}</i></div>`).join('');
}

function downloadReport() {
  const element = document.createElement('div');
  element.innerHTML = `<h1>YAML Security Scan Report</h1>${findings.map(f => `<p><b>${f.id}</b>: ${f.msg} - Severity: ${f.severity}</p>`).join('')}`;
  html2pdf().from(element).save('security_report.pdf');
}

function downloadAutoFixes() {
  const fixedYaml = autoFixes.map(f => jsyaml.dump(f)).join('\n---\n');
  const blob = new Blob([fixedYaml], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'autofixed.yaml';
  a.click();
  URL.revokeObjectURL(url);
}

const CIS_MAP = {
  privileged: 'CIS 5.2.1',
  allowPrivilegeEscalation: 'CIS 5.2.6',
  runAsRoot: 'CIS 5.2.5',
  imageLatestTag: 'CIS 5.4.1',
  resourceLimits: 'CIS 5.1.1',
  missingProbes: 'CIS 5.7.4',
  hostNamespace: 'CIS 5.2.2/5.2.3/5.2.4',
  defaultServiceAccount: 'CIS 5.1.5',
  networkPolicy: 'CIS 6.3.1'
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
    if (doc.spec?.template?.spec?.containers) {
      doc.spec.template.spec.containers.forEach(container => {
        if (container.securityContext?.privileged) {
          findings.push({ id: CIS_MAP.privileged, msg: `Privileged container in ${container.name}`, severity: 'High' });
          let patch = JSON.parse(JSON.stringify(doc));
          patch.spec.template.spec.containers.forEach(c => c.securityContext.privileged = false);
          autoFixes.push(patch);
        }
      });
    }
    const docString = JSON.stringify(doc);
    SECRET_PATTERNS.forEach(p => {
      if (p.regex.test(docString)) {
        findings.push({ id: 'Secrets', msg: p.desc, severity: 'Critical' });
      }
    });
  });
  renderResults();
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

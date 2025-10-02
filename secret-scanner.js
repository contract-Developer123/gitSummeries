const { exec, execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axios = require('axios');
const core = require('@actions/core');

// ✅ Custom Gitleaks rules
const customRules = `
[[rules]]
id = "strict-secret-detection"
description = "Detect likely passwords or secrets with high entropy"
regex = '''(?i)(password|passwd|pwd|secret|key|token|auth|access)[\\s"']*[=:][\\s"']*["']([A-Za-z0-9@#\\-_$%!]{10,})["']'''
tags = ["key", "secret", "generic", "password"]

[[rules]]
id = "jwt"
description = "JSON Web Token"
regex = '''eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+'''
tags = ["token", "jwt"]
`;

// ✅ Utility Functions
function writeCustomRules(rules) {
  const filePath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
  fs.writeFileSync(filePath, rules, 'utf8');
  return filePath;
}

function shouldSkip(filePath) {
  const skipList = ['node_modules', '.git', 'package.json', 'README.md'];
  return skipList.some(skip => filePath.includes(skip));
}

async function checkGitleaksInstalled() {
  return new Promise((resolve, reject) => {
    exec('which gitleaks', (err, stdout) => {
      if (err || !stdout.trim()) {
        reject(new Error('❌ Gitleaks is not installed or not found in PATH.'));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

async function runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath) {
  const cmd = `${gitleaksPath} detect --no-git --source="${scanDir}" --report-path="${reportPath}" --config="${rulesPath}" --report-format=json --verbose`;

  return new Promise((resolve, reject) => {
    exec(cmd, { shell: true, maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (stderr) console.warn('⚠️ Gitleaks STDERR:\n', stderr);
      if (err && err.code !== 1) {
        reject(new Error(`❌ Gitleaks failed: ${err.message}`));
        return;
      }
      resolve();
    });
  });
}

async function readReport(reportPath) {
  try {
    const data = fs.readFileSync(reportPath, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    console.error('❌ Failed to read Gitleaks report:', e.message);
    return [];
  }
}

function filterSecrets(results) {
  return results.filter(item => {
    if (!item.File || shouldSkip(item.File)) return false;
    if (/["']?\$\{?[A-Z0-9_]+\}?["']?/.test(item.Match)) return false;
    return true;
  });
}

function mapToApiFormat(item) {
  return {
    RuleID: item.RuleID,
    Description: item.Description,
    File: item.File,
    Match: item.Match,
    Secret: item.Secret,
    StartLine: String(item.StartLine ?? ''),
    EndLine: String(item.EndLine ?? ''),
    StartColumn: String(item.StartColumn ?? ''),
    EndColumn: String(item.EndColumn ?? '')
  };
}

async function sendToApi(secrets) {
  const projectId = process.env.PROJECT_ID;
  if (!projectId) {
    console.warn('⚠️ PROJECT_ID not set. Skipping API upload.');
    return;
  }

  const apiUrl = `https://dev.neoTrak.io/open-pulse/project/update-secrets/${projectId}`;
  const headers = {
    'Content-Type': 'application/json',
    'x-api-key': process.env.X_API_KEY || '',
    'x-secret-key': process.env.X_SECRET_KEY || '',
    'x-tenant-key': process.env.X_TENANT_KEY || ''
  };

  const payload = secrets.map(mapToApiFormat);

  try {
    const res = await axios.post(apiUrl, payload, { headers });
    if (res.status >= 200 && res.status < 300) {
      console.log('✅ Secrets sent to API successfully.');
    } else {
      console.error(`❌ API error (${res.status}):`, res.data);
    }
  } catch (err) {
    console.error('❌ Failed to send secrets to API:', err.message);
  }
}

async function writeGitHubSummary(secrets) {
  if (!core) return;

  if (!secrets.length) {
    await core.summary
      .addHeading('🔐 Secret Scan Results')
      .addRaw('✅ No secrets found.\n')
      .write();
    return;
  }

  await core.summary
    .addHeading('🔐 Secret Scan Results')
    .addTable([
      [
        { data: '📄 File', header: true },
        { data: '🔍 Type', header: true },
        { data: '📌 Line', header: true },
        { data: '🧬 Match', header: true }
      ],
      ...secrets.map(item => [
        item.File.replace(/^.*\/sbom\//, 'sbom/'),
        item.Description,
        item.StartLine,
        item.Match.length > 40 ? item.Match.slice(0, 40) + '...' : item.Match
      ])
    ])
    .addLink('🔗 View Dashboard', 'https://dev.neoTrak.io')
    .write();
}

// ✅ Main Scanner
async function main() {
  try {
    console.log('🚀 Starting secret scan...');
    const scanDir = process.env.SCAN_DIR || process.cwd();
    const reportPath = path.join(os.tmpdir(), `secrets_report_${Date.now()}.json`);
    const rulesPath = writeCustomRules(customRules);
    const gitleaksPath = await checkGitleaksInstalled();

    await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);
    const results = await readReport(reportPath);
    if (!results.length) {
      console.log('✅ No secrets detected.');
      await writeGitHubSummary([]);
      return;
    }

    const filtered = filterSecrets(results);
    console.log(`🔐 Secrets detected: ${filtered.length}`);
    filtered.forEach(s => console.log('📄 Secret:', mapToApiFormat(s)));

    await sendToApi(filtered);
    await writeGitHubSummary(filtered);

  } catch (err) {
    console.error('❌ Secret scan failed:', err.message);
    process.exit(1);
  }
}

main();

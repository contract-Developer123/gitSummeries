const { exec } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const core = require('@actions/core');

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

function writeCustomRules(rules) {
  const filePath = path.join(os.tmpdir(), 'gitleaks-custom-rules.toml');
  fs.writeFileSync(filePath, rules, 'utf8');
  return filePath;
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
      // gitleaks returns exit code 1 if leaks found - treat as success here
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

async function writeGitHubSummary(secrets, durationStr = '') {
  if (!core) return;

  await core.summary.addHeading('Test Results');

  // Group secrets by file
  const fileStatus = {};
  secrets.forEach(item => {
    const file = item.File.replace(/^.*\/sbom\//, 'sbom/');
    fileStatus[file] = 'Fail ❌';
  });

  // If you want to show "Pass ✅" for files with no secrets, you need a list of all scanned files.
  // For now, only files with secrets will be shown.
  const tableRows = Object.entries(fileStatus).map(([file, status]) => [
    file,
    status
  ]);

  await core.summary
    .addTable([
      [
        { data: 'File', header: true },
        { data: 'Result', header: true }
      ],
      ...tableRows
    ])
    .addRaw(`⏰ Scan duration: ${durationStr}\n`)
    .addLink('🔗 View Dashboard', 'https://dev.neoTrak.io')
    .write();

  if (secrets.length === 0) {
    core.setOutput('scan_result', 'passed');
  } else {
    core.setFailed(`❌ Secrets found: ${secrets.length}`);
    core.setOutput('scan_result', 'failed');
  }
}

async function main() {
  try {
    console.log('🚀 Starting secret scan...');
    const scanDir = process.env.SCAN_DIR || process.cwd();
    const reportPath = path.join(os.tmpdir(), `secrets_report_${Date.now()}.json`);
    const rulesPath = writeCustomRules(customRules);
    const gitleaksPath = await checkGitleaksInstalled();

    const startTime = Date.now();
    await runGitleaks(scanDir, reportPath, rulesPath, gitleaksPath);
    const endTime = Date.now();

    const results = await readReport(reportPath);

    const durationMs = endTime - startTime;
    const durationMin = Math.floor(durationMs / 60000);
    const durationSec = Math.floor((durationMs % 60000) / 1000);
    const durationStr = `${durationMin}min ${durationSec}s`;

    console.log(`🔐 Secrets detected: ${results.length}`);
    console.log(`⏰ Scan duration: ${durationStr}`);

    // Pass duration to summary
    await writeGitHubSummary(results, durationStr);

  } catch (err) {
    console.error('❌ Secret scan failed:', err.message);
    core.setFailed(`Secret scan failed: ${err.message}`);
    process.exit(1);
  }
}

main();

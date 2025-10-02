const { spawn } = require('child_process');
const path = require('path');

// Always resolve paths relative to current script (even when called from root)
const basePath = __dirname;

const scanTypeRaw = process.env.SCAN_TYPE || '';
const scanTypes = scanTypeRaw
  .split(',')
  .map(type => type.trim().toLowerCase());

function runScript(scriptName) {
  const fullPath = path.join(basePath, scriptName); // point to the correct location
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [fullPath], { stdio: 'inherit' });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`❌ ${scriptName} exited with code ${code}`));
      }
    });

    proc.on('error', (err) => {
      reject(new Error(`❌ Failed to start ${scriptName}: ${err.message}`));
    });
  });
}

async function runScans() {
  try {
    const tasks = [];

    if (scanTypes.includes('secrets') || scanTypes.includes('secret')) {
      console.log('🧾 Running Secret scan...');
      tasks.push(runScript('secret-scanner.js'));
    }

    if (tasks.length === 0) {
      console.log(`⚠️ No valid SCAN_TYPE found in "${scanTypeRaw}". Skipping scans.`);
      process.exit(0);
    }

    for (const task of tasks) {
      await task;
    }

    console.log('✅ All scans completed successfully.');
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

runScans();

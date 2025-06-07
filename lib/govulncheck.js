const exec = require('@actions/exec');

class GovulncheckRunner {
  constructor(execModule = exec) {
    this.exec = execModule;
  }

  async install() {
    // Check if govulncheck is already installed
    try {
      await this.exec.exec('govulncheck', ['-version']);
      console.log('govulncheck is already installed');
      return;
    } catch (e) {
      console.log('govulncheck not found, installing...');
      await this.exec.exec('go', ['install', 'golang.org/x/vuln/cmd/govulncheck@latest']);
    }
  }

  async run() {
    let output = '';
    let errorOutput = '';
    
    const options = {
      listeners: {
        stdout: (data) => {
          output += data.toString();
        },
        stderr: (data) => {
          errorOutput += data.toString();
        }
      },
      ignoreReturnCode: true
    };
    
    const exitCode = await this.exec.exec('govulncheck', ['-json', './...'], options);
    
    return {
      output,
      errorOutput,
      exitCode
    };
  }
}

module.exports = GovulncheckRunner;
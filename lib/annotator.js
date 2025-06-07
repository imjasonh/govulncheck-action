const fs = require('fs').promises;
const path = require('path');

class AnnotationCreator {
  constructor(core, fsModule = fs) {
    this.core = core;
    this.fs = fsModule;
  }

  async createAnnotations(vulnerabilities, parser, workingDirectory = '.') {
    this.core.info(`Creating annotations for ${vulnerabilities.length} vulnerabilities`);
    
    const modules = parser.extractUniqueModules(vulnerabilities);
    const callSites = parser.extractCallSites(vulnerabilities);
    
    this.core.info(`Found ${modules.length} vulnerable modules and ${callSites.length} call sites`);
    
    // Annotate go.mod for vulnerable modules
    await this.annotateGoMod(modules, vulnerabilities, workingDirectory);
    
    // Annotate source files for call sites
    this.annotateCallSites(callSites);
  }

  async annotateGoMod(modules, vulnerabilities, workingDirectory) {
    if (modules.length === 0) return;
    
    const goModPath = path.join(workingDirectory, 'go.mod');
    let goModContent = '';
    
    try {
      goModContent = await this.fs.readFile(goModPath, 'utf8');
    } catch (error) {
      this.core.warning(`Could not read go.mod: ${error.message}`);
      return;
    }
    
    const goModLines = goModContent.split('\n');
    
    for (const module of modules) {
      // Find the vulnerability info for this module
      const vuln = vulnerabilities.find(v => 
        v.finding.trace && 
        v.finding.trace[0] && 
        v.finding.trace[0].module === module
      );
      
      // Find line in go.mod
      for (let i = 0; i < goModLines.length; i++) {
        if (goModLines[i].includes(module)) {
          const lineNumber = i + 1;
          let message = `Vulnerable module: ${module}`;
          
          if (vuln && vuln.finding.osv) {
            message += ` (${vuln.finding.osv})`;
          }
          
          this.core.info(`Creating annotation for ${module} at go.mod:${lineNumber}`);
          
          // GitHub Actions annotation format
          this.core.warning(message, {
            title: 'Security Vulnerability',
            file: 'go.mod',
            startLine: lineNumber,
            endLine: lineNumber
          });
          break;
        }
      }
    }
  }

  annotateCallSites(callSites) {
    for (const site of callSites) {
      let message = `Vulnerable code path: ${site.function}`;
      
      if (site.osv) {
        message += ` (${site.osv})`;
      }
      
      this.core.info(`Creating annotation for call site at ${site.filename}:${site.line}`);
      
      // GitHub Actions annotation format
      this.core.warning(message, {
        title: 'Security Vulnerability',
        file: site.filename,
        startLine: site.line,
        endLine: site.line
      });
    }
  }
}

module.exports = AnnotationCreator;
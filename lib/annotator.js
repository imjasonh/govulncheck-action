const fs = require('fs').promises;
const path = require('path');

class AnnotationCreator {
  constructor(core, fsModule = fs) {
    this.core = core;
    this.fs = fsModule;
  }

  async createAnnotations(vulnerabilities, parser, workingDirectory = '.') {
    const modules = parser.extractUniqueModules(vulnerabilities);
    const callSites = parser.extractCallSites(vulnerabilities);
    
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
          const annotation = {
            path: 'go.mod',
            start_line: i + 1,
            end_line: i + 1,
            annotation_level: 'warning',
            message: `Vulnerable module: ${module}`,
            title: 'Security Vulnerability'
          };
          
          if (vuln && vuln.finding.osv) {
            annotation.message += ` (${vuln.finding.osv})`;
          }
          
          this.core.warning(annotation.message, annotation);
          break;
        }
      }
    }
  }

  annotateCallSites(callSites) {
    for (const site of callSites) {
      const annotation = {
        path: site.filename,
        start_line: site.line,
        end_line: site.line,
        annotation_level: 'warning',
        message: `Vulnerable code path: ${site.function}`,
        title: 'Security Vulnerability'
      };
      
      if (site.osv) {
        annotation.message += ` (${site.osv})`;
      }
      
      this.core.warning(annotation.message, annotation);
    }
  }
}

module.exports = AnnotationCreator;
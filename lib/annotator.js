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
    
    // Check which modules have actual call sites
    const modulesWithCallSites = this.findModulesWithCallSites(vulnerabilities, callSites);
    
    // Annotate go.mod for vulnerable modules
    await this.annotateGoMod(modules, vulnerabilities, workingDirectory, modulesWithCallSites);
    
    // Annotate source files for call sites
    this.annotateCallSites(callSites, workingDirectory);
  }
  
  findModulesWithCallSites(vulnerabilities, callSites) {
    const modulesWithCallSites = new Map();
    
    // For each call site, find which module it belongs to
    for (const site of callSites) {
      const vuln = vulnerabilities.find(v => v.finding.osv === site.osv);
      if (vuln && vuln.finding.trace && vuln.finding.trace[0]) {
        const module = vuln.finding.trace[0].module;
        const version = vuln.finding.trace[0].version;
        const fixedVersion = vuln.finding.fixed_version;
        
        if (!modulesWithCallSites.has(module)) {
          modulesWithCallSites.set(module, {
            currentVersion: version,
            fixedVersion: fixedVersion,
            osvs: []
          });
        }
        
        if (!modulesWithCallSites.get(module).osvs.includes(site.osv)) {
          modulesWithCallSites.get(module).osvs.push(site.osv);
        }
      }
    }
    
    return modulesWithCallSites;
  }

  async annotateGoMod(modules, vulnerabilities, workingDirectory, modulesWithCallSites) {
    if (modules.length === 0) return;
    
    const goModPath = 'go.mod';
    let goModContent = '';
    
    try {
      goModContent = await this.fs.readFile(goModPath, 'utf8');
    } catch (error) {
      this.core.warning(`Could not read go.mod: ${error.message}`);
      return;
    }
    
    const goModLines = goModContent.split('\n');
    
    for (const module of modules) {
      // Find all vulnerabilities for this module
      const moduleVulns = vulnerabilities.filter(v => 
        v.finding.trace && 
        v.finding.trace[0] && 
        v.finding.trace[0].module === module
      );
      
      // Find line in go.mod
      for (let i = 0; i < goModLines.length; i++) {
        if (goModLines[i].includes(module)) {
          const lineNumber = i + 1;
          
          // Build detailed message
          let message = `⚠️ Security vulnerabilities found in ${module}\n\n`;
          
          // Sort vulnerabilities by OSV ID
          const sortedVulns = moduleVulns.sort((a, b) => {
            const aId = a.finding.osv || '';
            const bId = b.finding.osv || '';
            return aId.localeCompare(bId);
          });
          
          for (const vuln of sortedVulns) {
            if (vuln.finding.osv) {
              message += `• ${vuln.finding.osv}`;
              
              if (vuln.osvDetails) {
                message += `: ${vuln.osvDetails.summary || 'No summary available'}`;
                
                // Add CVE aliases if available
                if (vuln.osvDetails.aliases && vuln.osvDetails.aliases.length > 0) {
                  const cves = vuln.osvDetails.aliases.filter(a => a.startsWith('CVE-'));
                  if (cves.length > 0) {
                    message += ` (${cves.join(', ')})`;
                  }
                }
              }
              
              message += `\n`;
              
              // Add link to vulnerability database
              message += `  🔗 https://pkg.go.dev/vuln/${vuln.finding.osv}\n`;
              
              // Add fixed version info
              if (vuln.finding.fixed_version) {
                message += `  ✅ Fixed in: ${vuln.finding.fixed_version}\n`;
              }
              
              message += `\n`;
            }
          }
          
          // Add upgrade suggestion
          if (moduleVulns.length > 0 && moduleVulns[0].finding.fixed_version) {
            message += `💡 Recommended action: Update to ${moduleVulns[0].finding.fixed_version} or later`;
          }
          
          this.core.info(`Creating annotation for ${module} at go.mod:${lineNumber}`);
          
          // GitHub Actions annotation format
          const filePath = workingDirectory === '.' ? 'go.mod' : path.join(workingDirectory, 'go.mod');
          this.core.warning(message, {
            title: `${moduleVulns.length} vulnerabilities in ${module}`,
            file: filePath,
            startLine: lineNumber,
            endLine: lineNumber
          });
          
          // If this module has actual call sites, create a suggested edit
          if (modulesWithCallSites.has(module)) {
            const moduleInfo = modulesWithCallSites.get(module);
            if (moduleInfo.fixedVersion) {
              // Create a notice with the suggested fix
              const currentLine = goModLines[i];
              const suggestedLine = currentLine.replace(moduleInfo.currentVersion, moduleInfo.fixedVersion);
              
              let editMessage = `🔧 Suggested fix: Update this dependency to fix vulnerabilities that are actually being called in your code.\n\n`;
              editMessage += `Current: ${currentLine.trim()}\n`;
              editMessage += `Suggested: ${suggestedLine.trim()}\n\n`;
              editMessage += `This fixes ${moduleInfo.osvs.length} vulnerabilities that have active call sites in your code:\n`;
              editMessage += moduleInfo.osvs.sort().map(osv => `• ${osv}`).join('\n');
              
              this.core.notice(editMessage, {
                title: `Fix available for ${module}`,
                file: filePath,
                startLine: lineNumber,
                endLine: lineNumber
              });
            }
          }
          
          break;
        }
      }
    }
  }

  annotateCallSites(callSites, workingDirectory) {
    // Group call sites by OSV ID to avoid duplicate annotations
    const groupedSites = {};
    for (const site of callSites) {
      const key = `${site.filename}:${site.line}:${site.osv}`;
      if (!groupedSites[key]) {
        groupedSites[key] = site;
      }
    }
    
    for (const site of Object.values(groupedSites)) {
      // Build detailed message
      let message = `🚨 Vulnerable code detected\n\n`;
      message += `This code calls ${site.vulnerableFunction} which has a known vulnerability.\n\n`;
      
      if (site.osv) {
        message += `Vulnerability: ${site.osv}`;
        
        if (site.osvDetails) {
          message += ` - ${site.osvDetails.summary || 'No summary available'}`;
          
          // Add CVE aliases if available
          if (site.osvDetails.aliases && site.osvDetails.aliases.length > 0) {
            const cves = site.osvDetails.aliases.filter(a => a.startsWith('CVE-'));
            if (cves.length > 0) {
              message += `\nCVE: ${cves.join(', ')}`;
            }
          }
          
          // Add details if available
          if (site.osvDetails.details) {
            message += `\n\nDetails: ${site.osvDetails.details}`;
          }
        }
        
        message += `\n\n🔗 More info: https://pkg.go.dev/vuln/${site.osv}`;
      }
      
      if (site.fixedVersion) {
        message += `\n\n✅ Fix available: Update the dependency to ${site.fixedVersion} or later`;
      }
      
      this.core.info(`Creating annotation for call site at ${site.filename}:${site.line}`);
      
      // GitHub Actions annotation format
      // If we're in a subdirectory, prepend it to the filename
      const filePath = workingDirectory === '.' ? site.filename : path.join(workingDirectory, site.filename);
      
      const title = site.osv ? `Vulnerable code: ${site.osv}` : 'Vulnerable code detected';
      
      this.core.warning(message, {
        title: title,
        file: filePath,
        startLine: site.line,
        endLine: site.line
      });
    }
  }
}

module.exports = AnnotationCreator;
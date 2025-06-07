class VulnerabilityParser {
  parse(output) {
    const vulnerabilities = [];
    const lines = output.split('\n').filter(line => line.trim());
    
    for (const line of lines) {
      try {
        const json = JSON.parse(line);
        
        // Check for vulnerability findings
        if (json.finding) {
          vulnerabilities.push(json);
        }
      } catch (e) {
        // Skip non-JSON lines
      }
    }
    
    return vulnerabilities;
  }

  extractUniqueModules(vulnerabilities) {
    const modules = new Set();
    
    for (const vuln of vulnerabilities) {
      const finding = vuln.finding;
      if (finding.trace && finding.trace.length > 0 && finding.trace[0].module) {
        modules.add(finding.trace[0].module);
      }
    }
    
    return Array.from(modules);
  }

  extractCallSites(vulnerabilities) {
    const callSites = [];
    
    for (const vuln of vulnerabilities) {
      const finding = vuln.finding;
      if (finding.trace) {
        for (const frame of finding.trace) {
          if (frame.position && frame.position.filename) {
            callSites.push({
              filename: frame.position.filename,
              line: frame.position.line || 1,
              function: frame.function || 'unknown function',
              osv: finding.osv || null
            });
          }
        }
      }
    }
    
    return callSites;
  }
}

module.exports = VulnerabilityParser;
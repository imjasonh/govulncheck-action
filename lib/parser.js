class VulnerabilityParser {
  parse(output) {
    const vulnerabilities = [];
    
    // Try to parse as JSON Lines first (one JSON object per line)
    const lines = output.split('\n').filter(line => line.trim());
    console.log(`Parsing ${lines.length} lines of govulncheck output`);
    
    // Check if it's JSON lines format
    let isJsonLines = false;
    if (lines.length > 0) {
      try {
        JSON.parse(lines[0]);
        isJsonLines = true;
      } catch (e) {
        // Not JSON lines format
      }
    }
    
    if (isJsonLines) {
      // Parse as JSON lines
      for (const line of lines) {
        try {
          const json = JSON.parse(line);
          if (json.finding) {
            console.log(`Found vulnerability: ${JSON.stringify(json.finding.osv || json.finding)}`);
            vulnerabilities.push(json);
          }
        } catch (e) {
          // Skip non-JSON lines
        }
      }
    } else {
      // Parse as multi-line JSON objects
      // Split by lines that start with '{' at the beginning
      const jsonObjects = output.split(/\n(?=\{)/).filter(chunk => chunk.trim());
      console.log(`Found ${jsonObjects.length} JSON objects`);
      
      for (const jsonStr of jsonObjects) {
        try {
          const json = JSON.parse(jsonStr);
          if (json.finding) {
            console.log(`Found vulnerability: ${JSON.stringify(json.finding.osv || json.finding)}`);
            vulnerabilities.push(json);
          }
        } catch (e) {
          console.log(`Failed to parse JSON object: ${e.message}`);
        }
      }
    }
    
    console.log(`Parsed ${vulnerabilities.length} vulnerabilities`);
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
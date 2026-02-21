class SummaryGenerator {
  constructor(core) {
    this.core = core;
  }

  async generateSummary(vulnerabilities, parser, workingDirectory = '.') {
    const modules = parser.extractUniqueModules(vulnerabilities);
    const callSites = parser.extractCallSites(vulnerabilities);

    // Group vulnerabilities by module
    const vulnsByModule = new Map();
    for (const vuln of vulnerabilities) {
      if (vuln.finding.trace && vuln.finding.trace[0]) {
        const module = vuln.finding.trace[0].module;
        if (!vulnsByModule.has(module)) {
          vulnsByModule.set(module, []);
        }
        vulnsByModule.get(module).push(vuln);
      }
    }

    // Sort modules for consistent output
    const sortedModules = Array.from(vulnsByModule.keys()).sort();

    // Start building the summary
    await this.core.summary.addHeading('🔍 Govulncheck Security Report', 1).addEOL();

    if (vulnerabilities.length === 0) {
      await this.core.summary.addRaw('✅ No vulnerabilities found!').addEOL().write();
      return;
    }

    // Add overview
    await this.core.summary
      .addHeading('📊 Overview', 2)
      .addList([
        `Total vulnerabilities found: ${vulnerabilities.length}`,
        `Vulnerable modules: ${modules.length}`,
        `Vulnerable code locations: ${callSites.length}`,
      ])
      .addEOL();

    // Add vulnerable modules section
    await this.core.summary.addHeading('📦 Vulnerable Modules', 2).addEOL();

    for (const module of sortedModules) {
      const moduleVulns = vulnsByModule.get(module);
      const moduleInfo = moduleVulns[0].finding.trace[0];

      await this.core.summary
        .addHeading(`${module}`, 3)
        .addRaw(`Current version: ${moduleInfo.version}`)
        .addEOL()
        .addEOL();

      // Sort vulnerabilities by OSV ID
      const sortedVulns = moduleVulns.sort((a, b) => {
        const aId = a.finding.osv || '';
        const bId = b.finding.osv || '';
        return aId.localeCompare(bId);
      });

      // Create a table of vulnerabilities
      const tableRows = [['Vulnerability', 'Summary', 'Fixed Version', 'Details']];

      for (const vuln of sortedVulns) {
        const osvId = vuln.finding.osv;
        const summary = vuln.osvDetails?.summary || 'No summary available';
        const fixedVersion = vuln.finding.fixed_version || 'Not specified';

        let details = [];
        if (vuln.osvDetails?.aliases) {
          const cves = vuln.osvDetails.aliases.filter((a) => a.startsWith('CVE-'));
          if (cves.length > 0) {
            details.push(`CVE: ${cves.join(', ')}`);
          }
        }

        // For the link, we'll add it as a separate line after the table
        tableRows.push([
          osvId,
          summary.length > 60 ? summary.substring(0, 60) + '...' : summary,
          fixedVersion,
          details.join(', '),
        ]);
      }

      await this.core.summary.addTable(tableRows);

      // Add links separately since we can't put them in the table
      await this.core.summary.addEOL().addRaw('Links: ');
      for (let i = 0; i < sortedVulns.length; i++) {
        const vuln = sortedVulns[i];
        if (i > 0) await this.core.summary.addRaw(' | ');
        await this.core.summary.addLink(
          vuln.finding.osv,
          `https://pkg.go.dev/vuln/${vuln.finding.osv}`
        );
      }
      await this.core.summary.addEOL().addEOL();
    }

    // Add vulnerable code locations section
    if (callSites.length > 0) {
      await this.core.summary.addHeading('🚨 Vulnerable Code Locations', 2).addEOL();

      // Group call sites by file
      const callSitesByFile = new Map();
      for (const site of callSites) {
        const filePath =
          workingDirectory === '.' ? site.filename : `${workingDirectory}/${site.filename}`;
        if (!callSitesByFile.has(filePath)) {
          callSitesByFile.set(filePath, []);
        }
        callSitesByFile.get(filePath).push(site);
      }

      // Sort files
      const sortedFiles = Array.from(callSitesByFile.keys()).sort();

      for (const file of sortedFiles) {
        await this.core.summary.addHeading(`📄 ${file}`, 3);

        const sites = callSitesByFile.get(file);

        for (const site of sites) {
          await this.core.summary.addRaw(`• Line ${site.line}: calls ${site.vulnerableFunction}`);

          if (site.osv) {
            await this.core.summary
              .addRaw(' - ')
              .addLink(site.osv, `https://pkg.go.dev/vuln/${site.osv}`);
          }

          await this.core.summary.addEOL();
        }

        await this.core.summary.addEOL();
      }
    }

    // Add recommendations section
    await this.core.summary.addHeading('💡 Recommendations', 2).addEOL();

    const recommendations = [];

    // Find modules that need updates
    for (const module of sortedModules) {
      const moduleVulns = vulnsByModule.get(module);
      const fixedVersions = moduleVulns
        .map((v) => v.finding.fixed_version)
        .filter((v) => v)
        .sort();

      if (fixedVersions.length > 0) {
        // Get the latest fixed version
        const latestFix = fixedVersions[fixedVersions.length - 1];
        recommendations.push(`Update ${module} to version ${latestFix} or later`);
      }
    }

    if (recommendations.length > 0) {
      await this.core.summary.addList(recommendations);
    } else {
      await this.core.summary.addRaw('No specific version recommendations available.');
    }

    await this.core.summary
      .addEOL()
      .addSeparator()
      .addEOL()
      .addRaw('🔗 Learn more about these vulnerabilities:')
      .addEOL()
      .addRaw('• ')
      .addLink('Go Vulnerability Database', 'https://pkg.go.dev/vuln/')
      .addEOL()
      .addRaw('• ')
      .addLink('Govulncheck Documentation', 'https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck')
      .addEOL();

    // Write the summary
    await this.core.summary.write();
  }
}

export default SummaryGenerator;

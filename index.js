const core = require('@actions/core');
const GovulncheckRunner = require('./lib/govulncheck');
const VulnerabilityParser = require('./lib/parser');
const AnnotationCreator = require('./lib/annotator');

async function run(dependencies = {}) {
  // Allow dependency injection for testing
  const govulncheck = dependencies.govulncheck || new GovulncheckRunner();
  const parser = dependencies.parser || new VulnerabilityParser();
  const annotator = dependencies.annotator || new AnnotationCreator(core);

  try {
    const workingDirectory = core.getInput('working-directory');

    // Change to working directory
    if (workingDirectory !== '.') {
      process.chdir(workingDirectory);
    }

    // Install govulncheck
    core.info('Installing govulncheck...');
    await govulncheck.install();

    // Run govulncheck with JSON output
    core.info('Running govulncheck...');
    const { output, errorOutput } = await govulncheck.run();

    if (errorOutput) {
      core.warning(`govulncheck stderr: ${errorOutput}`);
    }

    // Parse JSON output
    const vulnerabilities = parser.parse(output);

    // Create annotations
    await annotator.createAnnotations(vulnerabilities, parser, '.');

    // Set outputs
    const hasVulnerabilities = vulnerabilities.length > 0;
    core.setOutput('vulnerabilities-found', hasVulnerabilities.toString());
    core.setOutput('vulnerability-count', vulnerabilities.length.toString());

    if (hasVulnerabilities) {
      core.warning(`Found ${vulnerabilities.length} vulnerabilities`);
    } else {
      core.info('No vulnerabilities found');
    }

    return { vulnerabilities, hasVulnerabilities };

  } catch (error) {
    core.setFailed(error.message);
    throw error;
  }
}

// Only run if this is the main module
if (require.main === module) {
  run();
}

module.exports = { run };

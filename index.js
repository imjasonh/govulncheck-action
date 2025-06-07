const core = require('@actions/core');
const GovulncheckRunner = require('./lib/govulncheck');
const VulnerabilityParser = require('./lib/parser');
const AnnotationCreator = require('./lib/annotator');
const SummaryGenerator = require('./lib/summary');

async function run(dependencies = {}) {
  // Allow dependency injection for testing
  const govulncheck = dependencies.govulncheck || new GovulncheckRunner();
  const parser = dependencies.parser || new VulnerabilityParser();
  const annotator = dependencies.annotator || new AnnotationCreator(core);
  const summaryGenerator = dependencies.summaryGenerator || new SummaryGenerator(core);

  try {
    const workingDirectory = core.getInput('working-directory');

    // Change to working directory
    if (workingDirectory !== '.') {
      core.info(`Changing working directory to: ${workingDirectory}`);
      process.chdir(workingDirectory);
    }

    // Install govulncheck if necessary.
    await govulncheck.install();

    // Run govulncheck with JSON output
    core.info('Running govulncheck...');
    const { output, errorOutput } = await govulncheck.run();

    if (errorOutput) {
      core.warning(`govulncheck stderr: ${errorOutput}`);
      
      // Check for critical errors that indicate govulncheck couldn't run properly
      if (errorOutput.includes('missing go.sum entry') || 
          errorOutput.includes('could not import') ||
          errorOutput.includes('invalid package name')) {
        throw new Error(`govulncheck failed due to missing dependencies. Please run 'go mod tidy' to update go.mod and go.sum files.\n\nError: ${errorOutput}`);
      }
    }

    // Log raw output for debugging
    core.info(`Raw govulncheck output length: ${output.length} characters`);
    if (output.length < 5000) {
      core.info(`Raw output: ${output}`);
    } else {
      core.info(`Raw output (first 1000 chars): ${output.substring(0, 1000)}...`);
    }

    // Parse JSON output
    const vulnerabilities = parser.parse(output);

    // Create annotations
    await annotator.createAnnotations(vulnerabilities, parser, workingDirectory);
    
    // Generate workflow summary
    await summaryGenerator.generateSummary(vulnerabilities, parser, workingDirectory);

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

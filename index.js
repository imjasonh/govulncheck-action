import * as core from '@actions/core';
import GovulncheckRunner from './lib/govulncheck.js';
import VulnerabilityParser from './lib/parser.js';
import AnnotationCreator from './lib/annotator.js';
import SummaryGenerator from './lib/summary.js';
import { fileURLToPath } from 'url';

async function run(dependencies = {}) {
  // Allow dependency injection for testing
  const coreLib = dependencies.core || core;
  const govulncheck = dependencies.govulncheck || new GovulncheckRunner();
  const parser = dependencies.parser || new VulnerabilityParser();
  const annotator = dependencies.annotator || new AnnotationCreator(coreLib);
  const summaryGenerator = dependencies.summaryGenerator || new SummaryGenerator(coreLib);

  try {
    const workingDirectory = coreLib.getInput('working-directory');

    // Change to working directory
    if (workingDirectory !== '.') {
      coreLib.info(`Changing working directory to: ${workingDirectory}`);
      process.chdir(workingDirectory);
    }

    // Install govulncheck if necessary.
    await govulncheck.install();

    // Run govulncheck with JSON output
    coreLib.info('Running govulncheck...');
    const { output, errorOutput } = await govulncheck.run();

    if (errorOutput) {
      coreLib.warning(`govulncheck stderr: ${errorOutput}`);

      // Check for critical errors that indicate govulncheck couldn't run properly
      if (
        errorOutput.includes('missing go.sum entry') ||
        errorOutput.includes('could not import') ||
        errorOutput.includes('invalid package name')
      ) {
        throw new Error(
          `govulncheck failed due to missing dependencies. Please run 'go mod tidy' to update go.mod and go.sum files.\n\nError: ${errorOutput}`
        );
      }
    }

    // Log raw output for debugging
    coreLib.info(`Raw govulncheck output length: ${output.length} characters`);
    if (output.length < 5000) {
      coreLib.info(`Raw output: ${output}`);
    } else {
      coreLib.info(`Raw output (first 1000 chars): ${output.substring(0, 1000)}...`);
    }

    // Parse JSON output
    const vulnerabilities = parser.parse(output);

    // Create annotations
    await annotator.createAnnotations(vulnerabilities, parser, workingDirectory);

    // Generate workflow summary
    await summaryGenerator.generateSummary(vulnerabilities, parser, workingDirectory);

    // Set outputs
    const hasVulnerabilities = vulnerabilities.length > 0;
    coreLib.setOutput('vulnerabilities-found', hasVulnerabilities.toString());
    coreLib.setOutput('vulnerability-count', vulnerabilities.length.toString());

    if (hasVulnerabilities) {
      coreLib.warning(`Found ${vulnerabilities.length} vulnerabilities`);
    } else {
      coreLib.info('No vulnerabilities found');
    }

    return { vulnerabilities, hasVulnerabilities };
  } catch (error) {
    coreLib.setFailed(error.message);
    throw error;
  }
}

// Only run if this is the main module
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  run();
}

export { run };

const core = require('@actions/core');
const fs = require('fs');
const path = require('path');
const GovulncheckRunner = require('./lib/govulncheck');
const VulnerabilityParser = require('./lib/parser');
const AnnotationCreator = require('./lib/annotator');
const SummaryGenerator = require('./lib/summary');

/**
 * Parse working directories from the input, supporting both comma and space delimiters.
 * Filters out duplicates and empty strings.
 * @param {string} input - The working-directory input string
 * @returns {string[]} - Array of unique, non-empty directory paths
 */
function parseWorkingDirectories(input) {
  if (!input) {
    return ['.'];
  }

  // Split by both comma and space, filter empty strings
  const dirs = input
    .split(/[,\s]+/)
    .map(dir => dir.trim())
    .filter(dir => dir.length > 0);

  // Remove duplicates
  const uniqueDirs = [...new Set(dirs)];

  return uniqueDirs.length > 0 ? uniqueDirs : ['.'];
}

/**
 * Check if a directory exists
 * @param {string} dir - Directory path to check
 * @param {object} fsModule - File system module (for testing)
 * @returns {boolean} - True if directory exists and is a directory
 */
function directoryExists(dir, fsModule = fs) {
  try {
    const stats = fsModule.statSync(dir);
    return stats.isDirectory();
  } catch (error) {
    return false;
  }
}

async function run(dependencies = {}) {
  // Allow dependency injection for testing
  const govulncheck = dependencies.govulncheck || new GovulncheckRunner();
  const parser = dependencies.parser || new VulnerabilityParser();
  const annotator = dependencies.annotator || new AnnotationCreator(core);
  const summaryGenerator = dependencies.summaryGenerator || new SummaryGenerator(core);
  const fsModule = dependencies.fs || fs;

  try {
    const workingDirectoryInput = core.getInput('working-directory');
    const workingDirectories = parseWorkingDirectories(workingDirectoryInput);

    core.info(`Processing ${workingDirectories.length} working director${workingDirectories.length === 1 ? 'y' : 'ies'}: ${workingDirectories.join(', ')}`);

    // Install govulncheck once (not per directory)
    await govulncheck.install();

    const allVulnerabilities = [];
    const originalCwd = process.cwd();

    // Process each directory
    for (const workingDirectory of workingDirectories) {
      // Resolve to absolute path
      const absolutePath = path.isAbsolute(workingDirectory) 
        ? workingDirectory 
        : path.join(originalCwd, workingDirectory);

      // Check if directory exists
      if (!directoryExists(absolutePath, fsModule)) {
        core.warning(`Directory not found, skipping: ${workingDirectory}`);
        continue;
      }

      // Change to working directory
      if (workingDirectory !== '.') {
        core.info(`Changing working directory to: ${workingDirectory}`);
        process.chdir(absolutePath);
      }

      try {
        // Run govulncheck with JSON output
        core.info(`Running govulncheck in ${workingDirectory}...`);
        const { output, errorOutput } = await govulncheck.run();

        if (errorOutput) {
          core.warning(`govulncheck stderr in ${workingDirectory}: ${errorOutput}`);
          
          // Check for critical errors that indicate govulncheck couldn't run properly
          if (errorOutput.includes('missing go.sum entry') || 
              errorOutput.includes('could not import') ||
              errorOutput.includes('invalid package name')) {
            throw new Error(`govulncheck failed in ${workingDirectory} due to missing dependencies. Please run 'go mod tidy' to update go.mod and go.sum files.\n\nError: ${errorOutput}`);
          }
        }

        // Log raw output for debugging
        core.info(`Raw govulncheck output length in ${workingDirectory}: ${output.length} characters`);
        if (output.length < 5000) {
          core.info(`Raw output: ${output}`);
        } else {
          core.info(`Raw output (first 1000 chars): ${output.substring(0, 1000)}...`);
        }

        // Parse JSON output
        const vulnerabilities = parser.parse(output);

        // Add directory context to each vulnerability
        vulnerabilities.forEach(vuln => {
          vuln.workingDirectory = workingDirectory;
        });

        allVulnerabilities.push(...vulnerabilities);

        core.info(`Found ${vulnerabilities.length} vulnerabilities in ${workingDirectory}`);
      } finally {
        // Always return to original directory
        process.chdir(originalCwd);
      }
    }

    // Filter duplicate vulnerabilities based on OSV ID
    const uniqueVulnerabilities = [];
    const seenOsvIds = new Set();

    for (const vuln of allVulnerabilities) {
      const osvId = vuln.finding?.osv;
      if (osvId && !seenOsvIds.has(osvId)) {
        seenOsvIds.add(osvId);
        uniqueVulnerabilities.push(vuln);
      } else if (!osvId) {
        // Include vulnerabilities without OSV IDs (shouldn't happen, but be safe)
        uniqueVulnerabilities.push(vuln);
      }
    }

    core.info(`Total unique vulnerabilities across all directories: ${uniqueVulnerabilities.length}`);

    // For annotations and summaries, we'll use the first working directory as context
    // or '.' if no directories were processed
    const contextDirectory = workingDirectories.length > 0 ? workingDirectories[0] : '.';

    // Create annotations
    await annotator.createAnnotations(uniqueVulnerabilities, parser, contextDirectory);
    
    // Generate workflow summary
    await summaryGenerator.generateSummary(uniqueVulnerabilities, parser, contextDirectory);

    // Set outputs
    const hasVulnerabilities = uniqueVulnerabilities.length > 0;
    core.setOutput('vulnerabilities-found', hasVulnerabilities.toString());
    core.setOutput('vulnerability-count', uniqueVulnerabilities.length.toString());

    if (hasVulnerabilities) {
      core.warning(`Found ${uniqueVulnerabilities.length} unique vulnerabilities across all directories`);
    } else {
      core.info('No vulnerabilities found');
    }

    return { vulnerabilities: uniqueVulnerabilities, hasVulnerabilities };

  } catch (error) {
    core.setFailed(error.message);
    throw error;
  }
}

// Only run if this is the main module
if (require.main === module) {
  run();
}

module.exports = { run, parseWorkingDirectories, directoryExists };

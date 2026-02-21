#!/usr/bin/env node

// Standalone script to run govulncheck locally
import GovulncheckRunner from './lib/govulncheck.js';
import VulnerabilityParser from './lib/parser.js';
import AnnotationCreator from './lib/annotator.js';

// Mock core for local testing
const mockCore = {
  info: (message) => console.log(`[INFO] ${message}`),
  warning: (message, properties) => {
    console.log(`[WARNING] ${message}`);
    if (properties) {
      console.log(`  Annotation:`, JSON.stringify(properties, null, 2));
    }
  },
  notice: (message, properties) => {
    console.log(`[NOTICE] ${message}`);
    if (properties) {
      console.log(`  Annotation:`, JSON.stringify(properties, null, 2));
    }
  },
};

async function runLocal() {
  const workingDirectory = process.argv[2] || './example';
  console.log(`Running govulncheck in ${workingDirectory}...`);

  const govulncheck = new GovulncheckRunner();
  const parser = new VulnerabilityParser();
  const annotator = new AnnotationCreator(mockCore);

  try {
    // Change to working directory
    if (workingDirectory !== '.') {
      console.log(`Changing to directory: ${workingDirectory}`);
      process.chdir(workingDirectory);
    }

    // Install/check govulncheck
    console.log('Checking govulncheck installation...');
    await govulncheck.install();

    // Run govulncheck
    console.log('Running govulncheck...');
    const { output, errorOutput } = await govulncheck.run();

    if (errorOutput) {
      console.log(`[STDERR] ${errorOutput}`);
    }

    // Show raw output length
    console.log(`[INFO] Raw output length: ${output.length} characters`);

    // Parse results
    const vulnerabilities = parser.parse(output);

    // Create annotations
    await annotator.createAnnotations(vulnerabilities, parser, '.');

    // Summary
    console.log('\n=== SUMMARY ===');
    console.log(`Total vulnerabilities found: ${vulnerabilities.length}`);

    if (vulnerabilities.length > 0) {
      console.log('\nVulnerabilities:');
      vulnerabilities.forEach((v, i) => {
        console.log(`\n${i + 1}. ${v.finding?.osv || 'Unknown'}`);
        if (v.finding?.trace) {
          console.log('   Trace:');
          v.finding.trace.forEach((t, j) => {
            console.log(
              `   ${j + 1}. ${t.module || t.package || 'unknown'} - ${
                t.function || 'unknown function'
              }`
            );
            if (t.position) {
              console.log(`      at ${t.position.filename}:${t.position.line}`);
            }
          });
        }
      });
    }
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

runLocal();

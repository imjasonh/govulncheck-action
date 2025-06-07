#!/usr/bin/env node

// Local test script to run the action without GitHub Actions environment
const path = require('path');
const { run } = require('./index');

// Mock the @actions/core module for local testing
const mockCore = {
  getInput: (name) => {
    const inputs = {
      'working-directory': process.argv[2] || './example'
    };
    return inputs[name] || '.';
  },
  info: (message) => {
    console.log(`[INFO] ${message}`);
  },
  warning: (message, properties) => {
    console.log(`[WARNING] ${message}`);
    if (properties) {
      console.log(`  Annotation properties:`, properties);
    }
  },
  setOutput: (name, value) => {
    console.log(`[OUTPUT] ${name}=${value}`);
  },
  setFailed: (message) => {
    console.error(`[ERROR] ${message}`);
    process.exit(1);
  }
};

// Replace the real @actions/core with our mock
require.cache[require.resolve('@actions/core')] = {
  exports: mockCore
};

// Run the action
async function testLocal() {
  console.log('Running govulncheck-action locally...');
  console.log(`Working directory: ${mockCore.getInput('working-directory')}`);
  console.log('---');
  
  try {
    const result = await run();
    console.log('---');
    console.log('Action completed successfully!');
    console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
  } catch (error) {
    console.error('Action failed:', error);
    process.exit(1);
  }
}

testLocal();

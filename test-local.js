import path from 'path';
import { run } from './index.js';

// Mock the @actions/core module for local testing
const mockCore = {
  getInput: (name) => {
    const inputs = {
      'working-directory': process.argv[2] || './example',
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
  },
  summary: {
    addHeading: () => mockCore.summary,
    addEOL: () => mockCore.summary,
    addRaw: () => mockCore.summary,
    addList: () => mockCore.summary,
    addTable: () => mockCore.summary,
    addLink: () => mockCore.summary,
    addSeparator: () => mockCore.summary,
    write: () => Promise.resolve(),
  },
  notice: (message, properties) => {
    console.log(`[NOTICE] ${message}`);
    if (properties) {
      console.log(`  Annotation properties:`, properties);
    }
  },
};

// Run the action
async function testLocal() {
  console.log('Running govulncheck-action locally...');
  console.log(`Working directory: ${mockCore.getInput('working-directory')}`);
  console.log('---');

  try {
    const result = await run({ core: mockCore });
    console.log('---');
    console.log('Action completed successfully!');
    console.log(`Found ${result.vulnerabilities.length} vulnerabilities`);
  } catch (error) {
    console.error('Action failed:', error);
    process.exit(1);
  }
}

testLocal();

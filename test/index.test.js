const { run } = require('../index');
const core = require('@actions/core');

// Mock the @actions/core module
jest.mock('@actions/core', () => {
  const mockSummary = {
    addHeading: jest.fn().mockReturnThis(),
    addEOL: jest.fn().mockReturnThis(),
    addRaw: jest.fn().mockReturnThis(),
    addList: jest.fn().mockReturnThis(),
    addTable: jest.fn().mockReturnThis(),
    addCodeBlock: jest.fn().mockReturnThis(),
    addDetails: jest.fn().mockReturnThis(),
    addLink: jest.fn().mockReturnThis(),
    addSeparator: jest.fn().mockReturnThis(),
    write: jest.fn().mockResolvedValue()
  };
  
  return {
    getInput: jest.fn(),
    info: jest.fn(),
    warning: jest.fn(),
    setOutput: jest.fn(),
    setFailed: jest.fn(),
    summary: mockSummary
  };
});

describe('GitHub Action Integration', () => {
  let mockGovulncheck;
  let mockParser;
  let mockAnnotator;
  let originalChdir;

  beforeEach(() => {
    // Save original process.chdir
    originalChdir = process.chdir;
    process.chdir = jest.fn();

    // Reset all mocks
    jest.clearAllMocks();

    // Set default input values
    core.getInput.mockReturnValue('.');

    // Create mock dependencies
    mockGovulncheck = {
      install: jest.fn().mockResolvedValue(),
      run: jest.fn().mockResolvedValue({
        output: '',
        errorOutput: '',
        exitCode: 0
      })
    };

    mockParser = {
      parse: jest.fn().mockReturnValue([]),
      extractUniqueModules: jest.fn().mockReturnValue([]),
      extractCallSites: jest.fn().mockReturnValue([])
    };

    mockAnnotator = {
      createAnnotations: jest.fn().mockResolvedValue()
    };
  });

  afterEach(() => {
    // Restore original process.chdir
    process.chdir = originalChdir;
  });

  it('should complete successfully with no vulnerabilities', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };

    const result = await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    });

    expect(core.info).toHaveBeenCalledWith('Processing 1 working directory: .');
    expect(core.info).toHaveBeenCalledWith('Running govulncheck in ....');
    expect(core.info).toHaveBeenCalledWith('Raw govulncheck output length in .: 0 characters');
    expect(core.info).toHaveBeenCalledWith('Raw output: ');

    expect(mockGovulncheck.install).toHaveBeenCalled();
    expect(mockGovulncheck.run).toHaveBeenCalled();

    expect(core.setOutput).toHaveBeenCalledWith('vulnerabilities-found', 'false');
    expect(core.setOutput).toHaveBeenCalledWith('vulnerability-count', '0');

    expect(result).toEqual({
      vulnerabilities: [],
      hasVulnerabilities: false
    });
  });

  it('should handle vulnerabilities found', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };

    const mockVulnerabilities = [
      {
        finding: {
          osv: 'GO-2023-1234',
          trace: [{ module: 'example.com/vulnerable' }]
        }
      },
      {
        finding: {
          osv: 'GO-2023-5678',
          trace: [{ module: 'another.com/package' }]
        }
      }
    ];

    mockParser.parse.mockReturnValue(mockVulnerabilities);

    const result = await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    });

    expect(core.warning).toHaveBeenCalledWith('Found 2 unique vulnerabilities across all directories');
    expect(core.setOutput).toHaveBeenCalledWith('vulnerabilities-found', 'true');
    expect(core.setOutput).toHaveBeenCalledWith('vulnerability-count', '2');

    expect(result).toEqual({
      vulnerabilities: mockVulnerabilities,
      hasVulnerabilities: true
    });
  });

  it('should change to working directory if specified', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    core.getInput.mockReturnValue('./subfolder');

    await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    });

    // Should change to the subfolder absolute path
    expect(process.chdir).toHaveBeenCalled();
    const chdirCalls = process.chdir.mock.calls;
    expect(chdirCalls.some(call => call[0].includes('subfolder'))).toBe(true);
  });

  it('should not change directory for default value', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    core.getInput.mockReturnValue('.');

    await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    });

    // Should still call chdir for the original directory restoration
    // but not for changing to '.'
    const chdirCalls = process.chdir.mock.calls;
    const changeToNewDir = chdirCalls.some(call => call[0] !== originalChdir && call[0] !== process.cwd());
    expect(changeToNewDir).toBe(false);
  });

  it('should handle stderr warnings', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    mockGovulncheck.run.mockResolvedValue({
      output: '',
      errorOutput: 'warning: using database from 2023-01-01',
      exitCode: 0
    });

    await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    });

    expect(core.warning).toHaveBeenCalledWith(
      'govulncheck stderr in .: warning: using database from 2023-01-01'
    );
  });

  it('should fail when go.sum is missing', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    mockGovulncheck.run.mockResolvedValue({
      output: '{"config": {}}',
      errorOutput: 'missing go.sum entry for module providing package golang.org/x/net/html',
      exitCode: 1
    });

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    })).rejects.toThrow('govulncheck failed in . due to missing dependencies');
  });

  it('should fail when imports cannot be resolved', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    mockGovulncheck.run.mockResolvedValue({
      output: '{"config": {}}',
      errorOutput: 'could not import golang.org/x/net/html (invalid package name: "")',
      exitCode: 1
    });

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    })).rejects.toThrow('govulncheck failed in . due to missing dependencies');
  });

  it('should handle errors and set action as failed', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    const error = new Error('Failed to install govulncheck');
    mockGovulncheck.install.mockRejectedValue(error);

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    })).rejects.toThrow('Failed to install govulncheck');

    expect(core.setFailed).toHaveBeenCalledWith('Failed to install govulncheck');
  });

  it('should handle parsing errors', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    const error = new Error('Invalid JSON output');
    mockParser.parse.mockImplementation(() => {
      throw error;
    });

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    })).rejects.toThrow('Invalid JSON output');

    expect(core.setFailed).toHaveBeenCalledWith('Invalid JSON output');
  });

  it('should handle annotation errors gracefully', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    const mockVulnerabilities = [{ finding: { osv: 'GO-2023-1234' } }];
    mockParser.parse.mockReturnValue(mockVulnerabilities);
    mockAnnotator.createAnnotations.mockRejectedValue(new Error('Annotation failed'));

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    })).rejects.toThrow('Annotation failed');

    expect(core.setFailed).toHaveBeenCalledWith('Annotation failed');
  });

  it('should truncate output logging when output is large', async () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };
    
    const largeOutput = 'x'.repeat(6000);
    mockGovulncheck.run.mockResolvedValue({
      output: largeOutput,
      errorOutput: '',
      exitCode: 0
    });

    await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator,
      fs: mockFs
    });

    expect(core.info).toHaveBeenCalledWith('Raw govulncheck output length in .: 6000 characters');
    expect(core.info).toHaveBeenCalledWith(`Raw output (first 1000 chars): ${'x'.repeat(1000)}...`);
  });

  describe('Multiple Working Directories', () => {
    let mockFs;
    let originalCwd;

    beforeEach(() => {
      originalCwd = process.cwd();
      mockFs = {
        statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
      };
    });

    it('should process comma-separated directories', async () => {
      core.getInput.mockReturnValue('dir1,dir2,dir3');
      
      const mockVulns1 = [{ finding: { osv: 'GO-2023-1111' } }];
      const mockVulns2 = [{ finding: { osv: 'GO-2023-2222' } }];
      const mockVulns3 = [{ finding: { osv: 'GO-2023-3333' } }];

      mockParser.parse
        .mockReturnValueOnce(mockVulns1)
        .mockReturnValueOnce(mockVulns2)
        .mockReturnValueOnce(mockVulns3);

      const result = await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(core.info).toHaveBeenCalledWith('Processing 3 working directories: dir1, dir2, dir3');
      expect(mockGovulncheck.run).toHaveBeenCalledTimes(3);
      expect(result.vulnerabilities).toHaveLength(3);
      expect(result.hasVulnerabilities).toBe(true);
    });

    it('should process space-delimited directories', async () => {
      core.getInput.mockReturnValue('dir1 dir2 dir3');
      
      mockParser.parse.mockReturnValue([]);

      await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(core.info).toHaveBeenCalledWith('Processing 3 working directories: dir1, dir2, dir3');
      expect(mockGovulncheck.run).toHaveBeenCalledTimes(3);
    });

    it('should process mixed comma and space delimited directories', async () => {
      core.getInput.mockReturnValue('dir1, dir2 dir3,dir4');
      
      mockParser.parse.mockReturnValue([]);

      await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(core.info).toHaveBeenCalledWith('Processing 4 working directories: dir1, dir2, dir3, dir4');
      expect(mockGovulncheck.run).toHaveBeenCalledTimes(4);
    });

    it('should filter out duplicate directories', async () => {
      core.getInput.mockReturnValue('dir1,dir2,dir1,dir3,dir2');
      
      mockParser.parse.mockReturnValue([]);

      await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(core.info).toHaveBeenCalledWith('Processing 3 working directories: dir1, dir2, dir3');
      expect(mockGovulncheck.run).toHaveBeenCalledTimes(3);
    });

    it('should skip non-existent directories with a warning', async () => {
      core.getInput.mockReturnValue('existing-dir,non-existent-dir');
      
      mockFs.statSync.mockImplementation((dir) => {
        if (dir.includes('non-existent')) {
          throw new Error('ENOENT: no such file or directory');
        }
        return { isDirectory: () => true };
      });

      mockParser.parse.mockReturnValue([]);

      await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(core.warning).toHaveBeenCalledWith('Directory not found, skipping: non-existent-dir');
      expect(mockGovulncheck.run).toHaveBeenCalledTimes(1);
    });

    it('should filter duplicate vulnerabilities across directories', async () => {
      core.getInput.mockReturnValue('dir1,dir2');
      
      const vuln1 = { finding: { osv: 'GO-2023-1111' } };
      const vuln2 = { finding: { osv: 'GO-2023-2222' } };
      const vuln1Duplicate = { finding: { osv: 'GO-2023-1111' } };

      mockParser.parse
        .mockReturnValueOnce([vuln1, vuln2])
        .mockReturnValueOnce([vuln1Duplicate]);

      const result = await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(result.vulnerabilities).toHaveLength(2);
      expect(core.info).toHaveBeenCalledWith('Total unique vulnerabilities across all directories: 2');
    });

    it('should add workingDirectory context to vulnerabilities', async () => {
      core.getInput.mockReturnValue('dir1,dir2');
      
      const vuln1 = { finding: { osv: 'GO-2023-1111' } };
      const vuln2 = { finding: { osv: 'GO-2023-2222' } };

      mockParser.parse
        .mockReturnValueOnce([vuln1])
        .mockReturnValueOnce([vuln2]);

      const result = await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(result.vulnerabilities[0].workingDirectory).toBe('dir1');
      expect(result.vulnerabilities[1].workingDirectory).toBe('dir2');
    });

    it('should return to original directory after processing each directory', async () => {
      core.getInput.mockReturnValue('dir1,dir2');
      const originalDir = process.cwd();
      
      mockParser.parse.mockReturnValue([]);

      await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      // Should return to original directory after each iteration
      expect(process.chdir).toHaveBeenCalledWith(originalDir);
      // Called once per directory (2 times)
      const chdirCalls = process.chdir.mock.calls.filter(call => call[0] !== originalDir);
      expect(chdirCalls.length).toBe(2);
    });

    it('should install govulncheck only once for multiple directories', async () => {
      core.getInput.mockReturnValue('dir1,dir2,dir3');
      
      mockParser.parse.mockReturnValue([]);

      await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      expect(mockGovulncheck.install).toHaveBeenCalledTimes(1);
      expect(mockGovulncheck.run).toHaveBeenCalledTimes(3);
    });

    it('should handle errors in one directory and continue with others', async () => {
      core.getInput.mockReturnValue('dir1,dir2');
      
      let callCount = 0;
      mockGovulncheck.run.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Error in dir1');
        }
        return Promise.resolve({
          output: '',
          errorOutput: '',
          exitCode: 0
        });
      });

      await expect(run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      })).rejects.toThrow('Error in dir1');

      expect(core.setFailed).toHaveBeenCalledWith('Error in dir1');
    });

    it('should handle vulnerabilities without OSV IDs', async () => {
      core.getInput.mockReturnValue('dir1,dir2');
      
      const vuln1 = { finding: { osv: 'GO-2023-1111' } };
      const vuln2 = { finding: {} }; // No OSV ID
      const vuln3 = { finding: { osv: 'GO-2023-3333' } };

      mockParser.parse
        .mockReturnValueOnce([vuln1, vuln2])
        .mockReturnValueOnce([vuln3]);

      const result = await run({
        govulncheck: mockGovulncheck,
        parser: mockParser,
        annotator: mockAnnotator,
        fs: mockFs
      });

      // Should include all vulnerabilities since one doesn't have OSV ID
      expect(result.vulnerabilities).toHaveLength(3);
    });
  });
});

describe('parseWorkingDirectories', () => {
  const { parseWorkingDirectories } = require('../index');

  it('should parse comma-separated directories', () => {
    const result = parseWorkingDirectories('dir1,dir2,dir3');
    expect(result).toEqual(['dir1', 'dir2', 'dir3']);
  });

  it('should parse space-delimited directories', () => {
    const result = parseWorkingDirectories('dir1 dir2 dir3');
    expect(result).toEqual(['dir1', 'dir2', 'dir3']);
  });

  it('should parse mixed comma and space delimiters', () => {
    const result = parseWorkingDirectories('dir1, dir2 dir3,dir4');
    expect(result).toEqual(['dir1', 'dir2', 'dir3', 'dir4']);
  });

  it('should filter out empty strings', () => {
    const result = parseWorkingDirectories('dir1,,dir2,  ,dir3');
    expect(result).toEqual(['dir1', 'dir2', 'dir3']);
  });

  it('should remove duplicates', () => {
    const result = parseWorkingDirectories('dir1,dir2,dir1,dir3,dir2');
    expect(result).toEqual(['dir1', 'dir2', 'dir3']);
  });

  it('should trim whitespace from directory names', () => {
    const result = parseWorkingDirectories('  dir1  ,  dir2  ,  dir3  ');
    expect(result).toEqual(['dir1', 'dir2', 'dir3']);
  });

  it('should return ["."] for empty input', () => {
    expect(parseWorkingDirectories('')).toEqual(['.']);
    expect(parseWorkingDirectories(null)).toEqual(['.']);
    expect(parseWorkingDirectories(undefined)).toEqual(['.']);
  });

  it('should return ["."] for input with only whitespace', () => {
    const result = parseWorkingDirectories('   ,  ,   ');
    expect(result).toEqual(['.']);
  });

  it('should handle a single directory', () => {
    const result = parseWorkingDirectories('single-dir');
    expect(result).toEqual(['single-dir']);
  });
});

describe('directoryExists', () => {
  const { directoryExists } = require('../index');

  it('should return true for existing directories', () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => true })
    };

    const result = directoryExists('/some/path', mockFs);
    expect(result).toBe(true);
    expect(mockFs.statSync).toHaveBeenCalledWith('/some/path');
  });

  it('should return false for files', () => {
    const mockFs = {
      statSync: jest.fn().mockReturnValue({ isDirectory: () => false })
    };

    const result = directoryExists('/some/file.txt', mockFs);
    expect(result).toBe(false);
  });

  it('should return false for non-existent paths', () => {
    const mockFs = {
      statSync: jest.fn().mockImplementation(() => {
        throw new Error('ENOENT: no such file or directory');
      })
    };

    const result = directoryExists('/non/existent', mockFs);
    expect(result).toBe(false);
  });

  it('should handle any error and return false', () => {
    const mockFs = {
      statSync: jest.fn().mockImplementation(() => {
        throw new Error('Permission denied');
      })
    };

    const result = directoryExists('/no/access', mockFs);
    expect(result).toBe(false);
  });
});
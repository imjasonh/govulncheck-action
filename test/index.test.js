const { run } = require('../index');
const core = require('@actions/core');

// Mock the @actions/core module
jest.mock('@actions/core', () => ({
  getInput: jest.fn(),
  info: jest.fn(),
  warning: jest.fn(),
  setOutput: jest.fn(),
  setFailed: jest.fn()
}));

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
    const result = await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator
    });

    expect(core.info).toHaveBeenCalledWith('Installing govulncheck...');
    expect(core.info).toHaveBeenCalledWith('Running govulncheck...');
    expect(core.info).toHaveBeenCalledWith('No vulnerabilities found');

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
      annotator: mockAnnotator
    });

    expect(core.warning).toHaveBeenCalledWith('Found 2 vulnerabilities');
    expect(core.setOutput).toHaveBeenCalledWith('vulnerabilities-found', 'true');
    expect(core.setOutput).toHaveBeenCalledWith('vulnerability-count', '2');

    expect(mockAnnotator.createAnnotations).toHaveBeenCalledWith(
      mockVulnerabilities,
      mockParser,
      '.'
    );

    expect(result).toEqual({
      vulnerabilities: mockVulnerabilities,
      hasVulnerabilities: true
    });
  });

  it('should change to working directory if specified', async () => {
    core.getInput.mockReturnValue('./subfolder');

    await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator
    });

    expect(process.chdir).toHaveBeenCalledWith('./subfolder');
  });

  it('should not change directory for default value', async () => {
    core.getInput.mockReturnValue('.');

    await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator
    });

    expect(process.chdir).not.toHaveBeenCalled();
  });

  it('should handle stderr warnings', async () => {
    mockGovulncheck.run.mockResolvedValue({
      output: '',
      errorOutput: 'warning: using database from 2023-01-01',
      exitCode: 0
    });

    await run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator
    });

    expect(core.warning).toHaveBeenCalledWith(
      'govulncheck stderr: warning: using database from 2023-01-01'
    );
  });

  it('should handle errors and set action as failed', async () => {
    const error = new Error('Failed to install govulncheck');
    mockGovulncheck.install.mockRejectedValue(error);

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator
    })).rejects.toThrow('Failed to install govulncheck');

    expect(core.setFailed).toHaveBeenCalledWith('Failed to install govulncheck');
  });

  it('should handle parsing errors', async () => {
    const error = new Error('Invalid JSON output');
    mockParser.parse.mockImplementation(() => {
      throw error;
    });

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator
    })).rejects.toThrow('Invalid JSON output');

    expect(core.setFailed).toHaveBeenCalledWith('Invalid JSON output');
  });

  it('should handle annotation errors gracefully', async () => {
    const mockVulnerabilities = [{ finding: { osv: 'GO-2023-1234' } }];
    mockParser.parse.mockReturnValue(mockVulnerabilities);
    mockAnnotator.createAnnotations.mockRejectedValue(new Error('Annotation failed'));

    await expect(run({
      govulncheck: mockGovulncheck,
      parser: mockParser,
      annotator: mockAnnotator
    })).rejects.toThrow('Annotation failed');

    expect(core.setFailed).toHaveBeenCalledWith('Annotation failed');
  });
});
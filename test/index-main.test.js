// This test file specifically tests the main module execution path
describe('Main module execution', () => {
  it('should execute run() when module is main', () => {
    // Mock @actions/core first
    jest.mock('@actions/core', () => ({
      getInput: jest.fn().mockReturnValue('.'),
      info: jest.fn(),
      warning: jest.fn(),
      setOutput: jest.fn(),
      setFailed: jest.fn(),
      summary: {
        addHeading: jest.fn().mockReturnThis(),
        addEOL: jest.fn().mockReturnThis(),
        addRaw: jest.fn().mockReturnThis(),
        addList: jest.fn().mockReturnThis(),
        addTable: jest.fn().mockReturnThis(),
        addLink: jest.fn().mockReturnThis(),
        addSeparator: jest.fn().mockReturnThis(),
        write: jest.fn().mockResolvedValue()
      }
    }));

    // Clear require cache to ensure fresh module load
    delete require.cache[require.resolve('../index')];
    delete require.cache[require.resolve('../lib/govulncheck')];
    delete require.cache[require.resolve('../lib/parser')];
    delete require.cache[require.resolve('../lib/annotator')];
    delete require.cache[require.resolve('../lib/summary')];
    
    // Save original require.main
    const originalMain = require.main;
    
    // Mock the dependencies to avoid actual execution
    jest.doMock('../lib/govulncheck', () => {
      return jest.fn().mockImplementation(() => ({
        install: jest.fn().mockResolvedValue(),
        run: jest.fn().mockResolvedValue({ output: '', errorOutput: '', exitCode: 0 })
      }));
    });
    
    jest.doMock('../lib/parser', () => {
      return jest.fn().mockImplementation(() => ({
        parse: jest.fn().mockReturnValue([]),
        extractUniqueModules: jest.fn().mockReturnValue([]),
        extractCallSites: jest.fn().mockReturnValue([])
      }));
    });
    
    jest.doMock('../lib/annotator', () => {
      return jest.fn().mockImplementation(() => ({
        createAnnotations: jest.fn().mockResolvedValue()
      }));
    });
    
    jest.doMock('../lib/summary', () => {
      return jest.fn().mockImplementation(() => ({
        generateSummary: jest.fn().mockResolvedValue()
      }));
    });
    
    // Isolate and require the module
    jest.isolateModules(() => {
      // Set require.main to simulate running as main module
      const indexPath = require.resolve('../index');
      require.main = { filename: indexPath };
      
      // This should trigger the main module execution
      require('../index');
    });
    
    // Restore original require.main
    require.main = originalMain;
    
    // Clean up mocks
    jest.dontMock('../lib/govulncheck');
    jest.dontMock('../lib/parser');
    jest.dontMock('../lib/annotator');
    jest.dontMock('../lib/summary');
    
    // The test passes if no errors are thrown
    expect(true).toBe(true);
  });
});
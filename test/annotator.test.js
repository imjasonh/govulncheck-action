const AnnotationCreator = require('../lib/annotator');

describe('AnnotationCreator', () => {
  let annotator;
  let mockCore;
  let mockFs;
  let mockParser;

  beforeEach(() => {
    mockCore = {
      warning: jest.fn(),
      info: jest.fn()
    };
    
    mockFs = {
      readFile: jest.fn()
    };
    
    mockParser = {
      extractUniqueModules: jest.fn(),
      extractCallSites: jest.fn()
    };
    
    annotator = new AnnotationCreator(mockCore, mockFs);
  });

  describe('createAnnotations', () => {
    it('should create annotations for modules and call sites', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable' }]
          }
        }
      ];
      
      mockParser.extractUniqueModules.mockReturnValue(['example.com/vulnerable']);
      mockParser.extractCallSites.mockReturnValue([
        {
          filename: 'main.go',
          line: 42,
          function: 'vulnerable.Function',
          osv: 'GO-2023-1234'
        }
      ]);
      
      mockFs.readFile.mockResolvedValue('module example.com/app\n\nrequire example.com/vulnerable v1.0.0');
      
      await annotator.createAnnotations(vulnerabilities, mockParser, '.');
      
      expect(mockParser.extractUniqueModules).toHaveBeenCalledWith(vulnerabilities);
      expect(mockParser.extractCallSites).toHaveBeenCalledWith(vulnerabilities);
      expect(mockCore.warning).toHaveBeenCalledTimes(2);
    });

    it('should handle empty vulnerabilities', async () => {
      mockParser.extractUniqueModules.mockReturnValue([]);
      mockParser.extractCallSites.mockReturnValue([]);
      
      await annotator.createAnnotations([], mockParser, '.');
      
      expect(mockCore.warning).not.toHaveBeenCalled();
    });
  });

  describe('annotateGoMod', () => {
    it('should annotate vulnerable modules in go.mod', async () => {
      const modules = ['example.com/vulnerable', 'another.com/package'];
      const vulnerabilities = [
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
      
      const goModContent = `module example.com/app

go 1.21

require (
    example.com/vulnerable v1.0.0
    another.com/package v2.1.0
)`;
      
      mockFs.readFile.mockResolvedValue(goModContent);
      
      // Create modulesWithCallSites map for testing
      const modulesWithCallSites = new Map();
      
      await annotator.annotateGoMod(modules, vulnerabilities, '.', modulesWithCallSites);
      
      expect(mockCore.warning).toHaveBeenCalledTimes(2);
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('⚠️ Security vulnerabilities found in example.com/vulnerable'),
        expect.objectContaining({
          file: 'go.mod',
          startLine: 6,
          endLine: 6,
          title: '1 vulnerabilities in example.com/vulnerable'
        })
      );
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('⚠️ Security vulnerabilities found in another.com/package'),
        expect.objectContaining({
          file: 'go.mod',
          startLine: 7,
          endLine: 7,
          title: '1 vulnerabilities in another.com/package'
        })
      );
    });

    it('should handle missing go.mod file', async () => {
      mockFs.readFile.mockRejectedValue(new Error('File not found'));
      
      await annotator.annotateGoMod(['example.com/vulnerable'], [], '.');
      
      expect(mockCore.warning).toHaveBeenCalledWith('Could not read go.mod: File not found');
    });

    it('should handle empty modules list', async () => {
      await annotator.annotateGoMod([], [], '.');
      
      expect(mockFs.readFile).not.toHaveBeenCalled();
      expect(mockCore.warning).not.toHaveBeenCalled();
    });

    it('should handle modules not found in go.mod', async () => {
      mockFs.readFile.mockResolvedValue('module example.com/app\n\ngo 1.21');
      
      await annotator.annotateGoMod(['nonexistent.com/module'], [], '.');
      
      expect(mockCore.warning).not.toHaveBeenCalled();
    });
  });

  describe('annotateCallSites', () => {
    it('should create annotations for vulnerable call sites', () => {
      const callSites = [
        {
          filename: 'main.go',
          line: 42,
          function: 'vulnerable.Function',
          osv: 'GO-2023-1234'
        },
        {
          filename: 'utils.go',
          line: 10,
          function: 'helper.Process',
          osv: null
        }
      ];
      
      annotator.annotateCallSites(callSites, '.');
      
      expect(mockCore.warning).toHaveBeenCalledTimes(2);
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('🚨 Vulnerable code detected'),
        expect.objectContaining({
          file: 'main.go',
          startLine: 42,
          endLine: 42,
          title: 'Vulnerable code: GO-2023-1234'
        })
      );
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('🚨 Vulnerable code detected'),
        expect.objectContaining({
          file: 'utils.go',
          startLine: 10,
          endLine: 10,
          title: 'Vulnerable code detected'
        })
      );
    });

    it('should handle empty call sites', () => {
      annotator.annotateCallSites([]);
      expect(mockCore.warning).not.toHaveBeenCalled();
    });

    it('should include OSV details with CVE aliases in call site annotations', () => {
      const callSites = [
        {
          filename: 'main.go',
          line: 42,
          vulnerableFunction: 'vulnerable.Function',
          osv: 'GO-2023-1234',
          osvDetails: {
            summary: 'Critical vulnerability in package',
            aliases: ['CVE-2023-1234', 'GHSA-xxxx-yyyy', 'CVE-2023-5678'],
            details: 'This vulnerability allows remote code execution'
          },
          fixedVersion: 'v1.2.3'
        }
      ];
      
      annotator.annotateCallSites(callSites, '.');
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('CVE: CVE-2023-1234, CVE-2023-5678'),
        expect.anything()
      );
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('Details: This vulnerability allows remote code execution'),
        expect.anything()
      );
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('✅ Fix available: Update the dependency to v1.2.3 or later'),
        expect.anything()
      );
    });

    it('should handle call sites without OSV details', () => {
      const callSites = [
        {
          filename: 'main.go',
          line: 42,
          vulnerableFunction: 'vulnerable.Function',
          osv: 'GO-2023-1234',
          osvDetails: null,
          fixedVersion: null
        }
      ];
      
      annotator.annotateCallSites(callSites, '.');
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.not.stringContaining('CVE:'),
        expect.anything()
      );
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.not.stringContaining('✅ Fix available:'),
        expect.anything()
      );
    });
  });

  describe('annotateGoMod with OSV details', () => {
    it('should include OSV details without aliases', async () => {
      const modules = ['example.com/vulnerable'];
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable' }],
            fixed_version: 'v1.2.3'
          },
          osvDetails: {
            summary: 'Critical vulnerability'
          }
        }
      ];
      
      const goModContent = 'module example.com/app\n\nrequire example.com/vulnerable v1.0.0';
      mockFs.readFile.mockResolvedValue(goModContent);
      
      await annotator.annotateGoMod(modules, vulnerabilities, '.', new Map());
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('GO-2023-1234: Critical vulnerability'),
        expect.anything()
      );
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('✅ Fixed in: v1.2.3'),
        expect.anything()
      );
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('💡 Recommended action: Update to v1.2.3 or later'),
        expect.anything()
      );
    });

    it('should include OSV details with CVE aliases', async () => {
      const modules = ['example.com/vulnerable'];
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable' }]
          },
          osvDetails: {
            summary: 'Critical vulnerability',
            aliases: ['CVE-2023-1234', 'GHSA-xxxx-yyyy', 'CVE-2023-5678']
          }
        }
      ];
      
      const goModContent = 'module example.com/app\n\nrequire example.com/vulnerable v1.0.0';
      mockFs.readFile.mockResolvedValue(goModContent);
      
      await annotator.annotateGoMod(modules, vulnerabilities, '.', new Map());
      
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('(CVE-2023-1234, CVE-2023-5678)'),
        expect.anything()
      );
    });

    it('should create suggested edits for modules with call sites', async () => {
      mockCore.notice = jest.fn();
      
      const modules = ['example.com/vulnerable'];
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
            fixed_version: 'v1.2.3'
          }
        }
      ];
      
      const goModContent = 'module example.com/app\n\nrequire example.com/vulnerable v1.0.0';
      mockFs.readFile.mockResolvedValue(goModContent);
      
      const modulesWithCallSites = new Map([
        ['example.com/vulnerable', {
          currentVersion: 'v1.0.0',
          fixedVersion: 'v1.2.3',
          osvs: ['GO-2023-1234', 'GO-2023-5678']
        }]
      ]);
      
      await annotator.annotateGoMod(modules, vulnerabilities, '.', modulesWithCallSites);
      
      expect(mockCore.notice).toHaveBeenCalledWith(
        expect.stringContaining('🔧 Suggested fix:'),
        expect.objectContaining({
          title: 'Fix available for example.com/vulnerable',
          file: 'go.mod',
          startLine: 3,
          endLine: 3
        })
      );
      expect(mockCore.notice).toHaveBeenCalledWith(
        expect.stringContaining('Current: require example.com/vulnerable v1.0.0'),
        expect.anything()
      );
      expect(mockCore.notice).toHaveBeenCalledWith(
        expect.stringContaining('Suggested: require example.com/vulnerable v1.2.3'),
        expect.anything()
      );
      expect(mockCore.notice).toHaveBeenCalledWith(
        expect.stringContaining('• GO-2023-1234'),
        expect.anything()
      );
    });

    it('should handle vulnerabilities without OSV IDs when sorting', async () => {
      const modules = ['example.com/vulnerable'];
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-5678',
            trace: [{ module: 'example.com/vulnerable' }]
          }
        },
        {
          finding: {
            // No OSV ID
            trace: [{ module: 'example.com/vulnerable' }]
          }
        },
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable' }]
          }
        }
      ];
      
      const goModContent = 'module example.com/app\n\nrequire example.com/vulnerable v1.0.0';
      mockFs.readFile.mockResolvedValue(goModContent);
      
      await annotator.annotateGoMod(modules, vulnerabilities, '.', new Map());
      
      // The vulnerabilities should be sorted with empty OSV IDs first
      expect(mockCore.warning).toHaveBeenCalledWith(
        expect.stringContaining('⚠️ Security vulnerabilities found in example.com/vulnerable'),
        expect.anything()
      );
    });
  });
});
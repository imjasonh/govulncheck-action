import SummaryGenerator from '../lib/summary.js';
import { describe, it, expect, beforeEach, jest } from '@jest/globals';

describe('SummaryGenerator', () => {
  let summaryGenerator;
  let mockCore;
  let mockParser;
  let mockSummary;

  beforeEach(() => {
    mockSummary = {
      addHeading: jest.fn().mockReturnThis(),
      addEOL: jest.fn().mockReturnThis(),
      addRaw: jest.fn().mockReturnThis(),
      addList: jest.fn().mockReturnThis(),
      addTable: jest.fn().mockReturnThis(),
      addLink: jest.fn().mockReturnThis(),
      addSeparator: jest.fn().mockReturnThis(),
      write: jest.fn().mockResolvedValue(),
    };

    mockCore = {
      summary: mockSummary,
    };

    mockParser = {
      extractUniqueModules: jest.fn(),
      extractCallSites: jest.fn(),
    };

    summaryGenerator = new SummaryGenerator(mockCore);
  });

  describe('generateSummary', () => {
    it('should generate summary with no vulnerabilities', async () => {
      mockParser.extractUniqueModules.mockReturnValue([]);
      mockParser.extractCallSites.mockReturnValue([]);

      await summaryGenerator.generateSummary([], mockParser, '.');

      expect(mockSummary.addHeading).toHaveBeenCalledWith('🔍 Govulncheck Security Report', 1);
      expect(mockSummary.addRaw).toHaveBeenCalledWith('✅ No vulnerabilities found!');
      expect(mockSummary.write).toHaveBeenCalled();
    });

    it('should generate summary with vulnerabilities sorted by OSV ID', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-5678',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
            fixed_version: 'v1.2.3',
          },
          osvDetails: {
            summary: 'Second vulnerability',
          },
        },
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
            fixed_version: 'v1.2.3',
          },
          osvDetails: {
            summary: 'First vulnerability',
          },
        },
      ];

      mockParser.extractUniqueModules.mockReturnValue(['example.com/vulnerable']);
      mockParser.extractCallSites.mockReturnValue([]);

      await summaryGenerator.generateSummary(vulnerabilities, mockParser, '.');

      // Check that table was called
      const tableCall = mockSummary.addTable.mock.calls[0][0];
      expect(tableCall[1][0]).toBe('GO-2023-1234'); // First row should be sorted first
      expect(tableCall[2][0]).toBe('GO-2023-5678'); // Second row should be sorted second
    });

    it('should include CVE aliases in vulnerability table', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
            fixed_version: 'v1.2.3',
          },
          osvDetails: {
            summary: 'Critical vulnerability',
            aliases: ['CVE-2023-1234', 'GHSA-xxxx-yyyy', 'CVE-2023-5678'],
          },
        },
      ];

      mockParser.extractUniqueModules.mockReturnValue(['example.com/vulnerable']);
      mockParser.extractCallSites.mockReturnValue([]);

      await summaryGenerator.generateSummary(vulnerabilities, mockParser, '.');

      const tableCall = mockSummary.addTable.mock.calls[0][0];
      expect(tableCall[1][3]).toBe('CVE: CVE-2023-1234, CVE-2023-5678');
    });

    it('should generate vulnerable code locations section', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
          },
        },
      ];

      const callSites = [
        {
          filename: 'main.go',
          line: 42,
          vulnerableFunction: 'vulnerable.Function',
          osv: 'GO-2023-1234',
        },
        {
          filename: 'utils.go',
          line: 10,
          vulnerableFunction: 'helper.Process',
          osv: 'GO-2023-5678',
        },
      ];

      mockParser.extractUniqueModules.mockReturnValue(['example.com/vulnerable']);
      mockParser.extractCallSites.mockReturnValue(callSites);

      await summaryGenerator.generateSummary(vulnerabilities, mockParser, '.');

      expect(mockSummary.addHeading).toHaveBeenCalledWith('🚨 Vulnerable Code Locations', 2);
      expect(mockSummary.addHeading).toHaveBeenCalledWith('📄 main.go', 3);
      expect(mockSummary.addRaw).toHaveBeenCalledWith('• Line 42: calls vulnerable.Function');
      expect(mockSummary.addLink).toHaveBeenCalledWith(
        'GO-2023-1234',
        'https://pkg.go.dev/vuln/GO-2023-1234'
      );
    });

    it('should handle call sites in subdirectory', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
          },
        },
      ];

      const callSites = [
        {
          filename: 'main.go',
          line: 42,
          vulnerableFunction: 'vulnerable.Function',
          osv: 'GO-2023-1234',
        },
      ];

      mockParser.extractUniqueModules.mockReturnValue(['example.com/vulnerable']);
      mockParser.extractCallSites.mockReturnValue(callSites);

      await summaryGenerator.generateSummary(vulnerabilities, mockParser, 'subdir');

      expect(mockSummary.addHeading).toHaveBeenCalledWith('📄 subdir/main.go', 3);
    });

    it('should generate recommendations with latest fixed versions', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
            fixed_version: 'v1.2.0',
          },
        },
        {
          finding: {
            osv: 'GO-2023-5678',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
            fixed_version: 'v1.2.3',
          },
        },
        {
          finding: {
            osv: 'GO-2023-9999',
            trace: [{ module: 'another.com/package', version: 'v2.0.0' }],
            fixed_version: 'v2.1.0',
          },
        },
      ];

      mockParser.extractUniqueModules.mockReturnValue([
        'example.com/vulnerable',
        'another.com/package',
      ]);
      mockParser.extractCallSites.mockReturnValue([]);

      await summaryGenerator.generateSummary(vulnerabilities, mockParser, '.');

      expect(mockSummary.addList).toHaveBeenCalledWith([
        'Update another.com/package to version v2.1.0 or later',
        'Update example.com/vulnerable to version v1.2.3 or later',
      ]);
    });

    it('should handle vulnerabilities without fixed versions', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [{ module: 'example.com/vulnerable', version: 'v1.0.0' }],
          },
        },
      ];

      mockParser.extractUniqueModules.mockReturnValue(['example.com/vulnerable']);
      mockParser.extractCallSites.mockReturnValue([]);

      await summaryGenerator.generateSummary(vulnerabilities, mockParser, '.');

      expect(mockSummary.addRaw).toHaveBeenCalledWith(
        'No specific version recommendations available.'
      );
    });

    it('should handle vulnerabilities without trace data', async () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
          },
        },
      ];

      mockParser.extractUniqueModules.mockReturnValue([]);
      mockParser.extractCallSites.mockReturnValue([]);

      await summaryGenerator.generateSummary(vulnerabilities, mockParser, '.');

      expect(mockSummary.write).toHaveBeenCalled();
    });
  });
});

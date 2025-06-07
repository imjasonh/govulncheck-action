const VulnerabilityParser = require('../lib/parser');

describe('VulnerabilityParser', () => {
  let parser;

  beforeEach(() => {
    parser = new VulnerabilityParser();
  });

  describe('parse', () => {
    it('should parse valid vulnerability findings', () => {
      const output = `
        {"finding":{"osv":"GO-2023-1234","trace":[{"module":"example.com/vulnerable"}]}}
        {"finding":{"osv":"GO-2023-5678","trace":[{"module":"another.com/package"}]}}
        {"progress":"scanning packages"}
      `;
      
      const vulnerabilities = parser.parse(output);
      
      expect(vulnerabilities).toHaveLength(2);
      expect(vulnerabilities[0].finding.osv).toBe('GO-2023-1234');
      expect(vulnerabilities[1].finding.osv).toBe('GO-2023-5678');
    });

    it('should handle empty output', () => {
      const vulnerabilities = parser.parse('');
      expect(vulnerabilities).toEqual([]);
    });

    it('should skip non-JSON lines', () => {
      const output = `
        Invalid JSON line
        {"finding":{"osv":"GO-2023-1234","trace":[{"module":"example.com/vulnerable"}]}}
        Another invalid line
      `;
      
      const vulnerabilities = parser.parse(output);
      expect(vulnerabilities).toHaveLength(1);
    });

    it('should ignore non-finding JSON objects', () => {
      const output = `
        {"progress":"scanning packages"}
        {"config":{"db":"latest"}}
        {"finding":{"osv":"GO-2023-1234","trace":[{"module":"example.com/vulnerable"}]}}
      `;
      
      const vulnerabilities = parser.parse(output);
      expect(vulnerabilities).toHaveLength(1);
    });
  });

  describe('extractUniqueModules', () => {
    it('should extract unique module names', () => {
      const vulnerabilities = [
        {
          finding: {
            trace: [{ module: 'example.com/vulnerable' }, { module: 'other.com/pkg' }]
          }
        },
        {
          finding: {
            trace: [{ module: 'example.com/vulnerable' }, { module: 'third.com/lib' }]
          }
        }
      ];
      
      const modules = parser.extractUniqueModules(vulnerabilities);
      
      expect(modules).toEqual(['example.com/vulnerable']);
    });

    it('should handle empty vulnerabilities', () => {
      const modules = parser.extractUniqueModules([]);
      expect(modules).toEqual([]);
    });

    it('should handle missing trace data', () => {
      const vulnerabilities = [
        { finding: {} },
        { finding: { trace: [] } },
        { finding: { trace: [{}] } }
      ];
      
      const modules = parser.extractUniqueModules(vulnerabilities);
      expect(modules).toEqual([]);
    });
  });

  describe('extractCallSites', () => {
    it('should extract call sites with position information', () => {
      const vulnerabilities = [
        {
          finding: {
            osv: 'GO-2023-1234',
            trace: [
              {
                position: { filename: 'main.go', line: 42 },
                function: 'vulnerable.Function'
              },
              {
                position: { filename: 'utils.go', line: 10 },
                function: 'helper.Process'
              }
            ]
          }
        }
      ];
      
      const callSites = parser.extractCallSites(vulnerabilities);
      
      expect(callSites).toHaveLength(2);
      expect(callSites[0]).toEqual({
        filename: 'main.go',
        line: 42,
        function: 'vulnerable.Function',
        osv: 'GO-2023-1234'
      });
      expect(callSites[1]).toEqual({
        filename: 'utils.go',
        line: 10,
        function: 'helper.Process',
        osv: 'GO-2023-1234'
      });
    });

    it('should handle missing position data', () => {
      const vulnerabilities = [
        {
          finding: {
            trace: [
              { function: 'no.Position' },
              { position: {} },
              { position: { filename: 'file.go' } }
            ]
          }
        }
      ];
      
      const callSites = parser.extractCallSites(vulnerabilities);
      
      expect(callSites).toHaveLength(1);
      expect(callSites[0]).toEqual({
        filename: 'file.go',
        line: 1,
        function: 'unknown function',
        osv: null
      });
    });

    it('should handle empty vulnerabilities', () => {
      const callSites = parser.extractCallSites([]);
      expect(callSites).toEqual([]);
    });
  });
});
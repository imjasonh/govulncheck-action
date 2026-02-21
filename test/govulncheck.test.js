import GovulncheckRunner from '../lib/govulncheck.js';
import { describe, it, expect, beforeEach, jest } from '@jest/globals';

describe('GovulncheckRunner', () => {
  let runner;
  let mockExec;

  beforeEach(() => {
    mockExec = {
      exec: jest.fn(),
    };
    runner = new GovulncheckRunner(mockExec);
  });

  describe('install', () => {
    it('should install govulncheck using go install', async () => {
      // First call to check if govulncheck exists will fail
      mockExec.exec.mockRejectedValueOnce(new Error('govulncheck not found'));
      // Second call to install will succeed
      mockExec.exec.mockResolvedValueOnce(0);

      await runner.install();

      expect(mockExec.exec).toHaveBeenCalledTimes(2);
      expect(mockExec.exec).toHaveBeenNthCalledWith(1, 'govulncheck', ['-version']);
      expect(mockExec.exec).toHaveBeenNthCalledWith(2, 'go', [
        'install',
        'golang.org/x/vuln/cmd/govulncheck@latest',
      ]);
    });

    it('should skip installation if govulncheck is already installed', async () => {
      // First call to check if govulncheck exists will succeed
      mockExec.exec.mockResolvedValueOnce(0);

      await runner.install();

      expect(mockExec.exec).toHaveBeenCalledTimes(1);
      expect(mockExec.exec).toHaveBeenCalledWith('govulncheck', ['-version']);
    });

    it('should throw error if installation fails', async () => {
      // First call to check if govulncheck exists will fail
      mockExec.exec.mockRejectedValueOnce(new Error('govulncheck not found'));
      // Second call to install will also fail
      mockExec.exec.mockRejectedValueOnce(new Error('Installation failed'));

      await expect(runner.install()).rejects.toThrow('Installation failed');
    });
  });

  describe('run', () => {
    it('should run govulncheck with JSON output', async () => {
      let capturedStdout;
      let capturedStderr;

      mockExec.exec.mockImplementation((cmd, args, options) => {
        capturedStdout = options.listeners.stdout;
        capturedStderr = options.listeners.stderr;

        // Simulate output
        capturedStdout(Buffer.from('{"finding": {"osv": "GO-2023-1234"}}'));
        capturedStderr(Buffer.from('warning: some warning'));

        return Promise.resolve(0);
      });

      const result = await runner.run('./...');

      expect(mockExec.exec).toHaveBeenCalledWith(
        'govulncheck',
        ['-json', './...'],
        expect.objectContaining({
          ignoreReturnCode: true,
          listeners: expect.objectContaining({
            stdout: expect.any(Function),
            stderr: expect.any(Function),
          }),
        })
      );

      expect(result).toEqual({
        output: '{"finding": {"osv": "GO-2023-1234"}}',
        errorOutput: 'warning: some warning',
        exitCode: 0,
      });
    });

    it('should capture non-zero exit codes', async () => {
      mockExec.exec.mockImplementation((cmd, args, options) => {
        options.listeners.stdout(Buffer.from(''));
        options.listeners.stderr(Buffer.from('error: vulnerabilities found'));
        return Promise.resolve(1);
      });

      const result = await runner.run();

      expect(result.exitCode).toBe(1);
      expect(result.errorOutput).toBe('error: vulnerabilities found');
    });

    it('should always run on ./...', async () => {
      mockExec.exec.mockResolvedValue(0);

      await runner.run();

      expect(mockExec.exec).toHaveBeenCalledWith(
        'govulncheck',
        ['-json', './...'],
        expect.any(Object)
      );
    });

    it('should handle execution errors', async () => {
      mockExec.exec.mockRejectedValue(new Error('Command not found'));

      await expect(runner.run()).rejects.toThrow('Command not found');
    });
  });
});

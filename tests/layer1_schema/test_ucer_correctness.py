import pytest
from pydantic import ValidationError
from core.ucer import UCER, ExecutionStep

def test_valid_ucer():
    ucer = UCER(
        intent="List files",
        steps=[
            ExecutionStep(adapter="bash", command="ls -la")
        ]
    )
    assert ucer.command_id is not None
    assert len(ucer.steps) == 1
    assert ucer.steps[0].adapter == "bash"

def test_invalid_adapter_rejected():
    with pytest.raises(ValidationError):
        UCER(
            intent="Hack",
            steps=[
                ExecutionStep(adapter="invalid_shell", command="echo 1")
            ]
        )

def test_missing_command_rejected():
    with pytest.raises(ValidationError):
        ExecutionStep(adapter="bash") # missing command

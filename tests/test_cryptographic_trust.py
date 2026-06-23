import pytest
import os
import asyncio
from core.ucer import UCER, ExecutionStep
from core.executor import UniversalExecutor
from core.types import Capability, ExecutionContext
from core.db import Database
from utils.cryptography import generate_key_pair

@pytest.mark.asyncio
async def test_ucer_cryptographic_trust_chain(tmp_path):
    # Setup temporary environment
    db_path = tmp_path / "test_trust.db"
    db = Database(str(db_path))
    
    # Generate keys for testing
    priv, pub = generate_key_pair()
    cp_priv_path = tmp_path / "cp_private.pem"
    cp_pub_path = tmp_path / "cp_public.pem"
    with open(cp_priv_path, "wb") as f: f.write(priv)
    with open(cp_pub_path, "wb") as f: f.write(pub)
    
    # Configure mock config paths
    from core.config import config
    config.cp_private_key_path = str(cp_priv_path)
    config.cp_public_key_path = str(cp_pub_path)
    
    executor = UniversalExecutor(db=db)
    
    # Create a UCER
    ucer = UCER(
        intent="List files in root",
        steps=[ExecutionStep(adapter="bash", command="ls /")]
    )
    
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    # 1. Sign and Verify
    ucer.sign_intent(priv)
    assert ucer.canonical_hash is not None
    assert ucer.control_signature is not None
    assert ucer.verify_integrity(pub) is True
    
    # 2. Tamper Detection
    original_intent = ucer.intent
    ucer.intent = "MALICIOUS INTENT"
    assert ucer.verify_integrity(pub) is False
    
    # Restore intent
    ucer.intent = original_intent
    assert ucer.verify_integrity(pub) is True
    
    # 3. Execution Integration
    # Mock the adapter to avoid Docker dependency in tests
    from unittest.mock import MagicMock
    executor.unified.adapters["bash"] = MagicMock()
    executor.unified.adapters["bash"].run.return_value = {"stdout": "verified", "stderr": "", "exit_code": 0}
    
    # This should pass integrity check internally
    ucer = await executor.execute_ucer(ucer, context=context)
    assert ucer.status == "completed"

@pytest.mark.asyncio
async def test_tampered_ucer_execution_rejection(tmp_path):
    db_path = tmp_path / "test_reject.db"
    db = Database(str(db_path))
    
    priv, pub = generate_key_pair()
    cp_priv_path = tmp_path / "cp_reject_private.pem"
    cp_pub_path = tmp_path / "cp_reject_public.pem"
    with open(cp_priv_path, "wb") as f: f.write(priv)
    with open(cp_pub_path, "wb") as f: f.write(pub)
    
    from core.config import config
    config.cp_private_key_path = str(cp_priv_path)
    config.cp_public_key_path = str(cp_pub_path)
    
    executor = UniversalExecutor(db=db)
    
    ucer = UCER(
        intent="Safe Command",
        steps=[ExecutionStep(adapter="bash", command="whoami")]
    )
    
    # Sign it legitimately
    ucer.sign_intent(priv)
    
    # Tamper with a step after signing
    ucer.steps[0].command = "rm -rf /"
    
    context = ExecutionContext(capabilities={Capability.EXEC, Capability.DELETE_ROOT})
    
    with pytest.raises(Exception) as excinfo:
        await executor.execute_ucer(ucer, context=context)
    
    # Note: Depending on implementation it might be SecurityError or similar
    assert "Integrity Check Failed" in str(excinfo.value)

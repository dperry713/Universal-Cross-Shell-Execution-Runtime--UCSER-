import json
import hashlib
from typing import Dict, Any
from core.ucer import UCER

class GoldenValidator:
    """
    Validates UCERs against Golden expected hashes.
    """
    
    @staticmethod
    def hash_ucer_structure(ucer: UCER) -> str:
        """
        Hashes the logical structure of a UCER (ignoring random UUIDs).
        """
        steps_data = []
        for step in ucer.steps:
            steps_data.append({
                "adapter": step.adapter,
                "command": step.command.strip()
            })
            
        data = json.dumps({"intent": ucer.intent, "steps": steps_data}, sort_keys=True)
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
        
    @staticmethod
    def validate_golden(ucer: UCER, expected_hash: str) -> bool:
        """
        Returns True if the generated UCER matches the golden hash.
        """
        return GoldenValidator.hash_ucer_structure(ucer) == expected_hash

import hashlib
import json
import numba
import numpy as np
from typing import Dict, Any

class UCKCore:
    """
    UCSER Core-Kernel (uCK).
    Provides low-level optimized primitives for security and integrity.
    Uses Numba JIT for C-level execution speeds on critical paths.
    """
    
    @staticmethod
    @numba.jit(nopython=True, cache=True)
    def fast_xor_hash(byte_arrays: np.ndarray) -> bytes:
        """
        Example of a low-level XOR-based aggregation for multi-step integrity.
        This represents an optimized low-level path for batch verification.
        """
        # Numba logic for fast byte manipulation
        res = byte_arrays[0].copy()
        for i in range(1, len(byte_arrays)):
            for j in range(len(res)):
                res[j] ^= byte_arrays[i][j]
        return res

    @staticmethod
    def compute_canonical_hash_uck(data: dict) -> str:
        """
        High-speed canonical hashing. 
        Optimizes serialization and utilizes SHA-256 (C-implementation).
        """
        # 1. Faster serialization (ensure deterministic keys)
        serialized = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        # 2. Direct SHA-256 (Hashlib uses OpenSSL/C under the hood)
        return hashlib.sha256(serialized).hexdigest()

class UCKAuditor:
    """
    Low-level AST auditor logic.
    Focuses on non-recursive, high-frequency token inspection.
    """
    
    @staticmethod
    def fast_scan_tokens(tokens: list, forbidden: set) -> list:
        """
        Optimized flat-scan of command tokens.
        Bypasses recursive visitor overhead for simple intents.
        """
        findings = []
        # Pre-convert to list for faster iteration if needed
        for t in tokens:
            if t in forbidden:
                findings.append(f"Forbidden token: {t}")
        return findings

import os
import requests
import json
import uuid
import re
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from pydantic import ValidationError

class LLMClient(ABC):
    @abstractmethod
    def to_ucer(self, intent: str) -> dict:
        """
        Translates a natural language intent into a strict UCER dictionary schema.
        Must return ONLY validated JSON matching the UCER specification.
        """
        pass

class BlacklistedAIProxyClient(LLMClient):
    def __init__(self):
        self.base_url = os.getenv("LLM_BASE_URL", "https://127.0.0.1:8000")
        self.token = os.getenv("LLM_API_TOKEN")

        if not self.token:
            raise RuntimeError("Missing LLM_API_TOKEN in environment variables.")

    def request(self, payload):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        # SSL verification enabled for production security.
        return requests.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=15,
            verify=True 
        )

    def _extract_json(self, text: str) -> dict:
        """Robustly extracts JSON from LLM response using markdown fences or raw search."""
        match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            return json.loads(match.group(1).strip())
        
        # Fallback to looking for the first { and last }
        match = re.search(r'(\{.*\})', text, re.DOTALL)
        if match:
            return json.loads(match.group(1).strip())
            
        raise ValueError("No valid JSON structure found in LLM response.")

    def to_ucer(self, intent: str) -> dict:
        system_prompt = '''You are the Semantic Compiler for SDER.
Output ONLY valid JSON inside a ```json ``` block. Schema:
{
  "command_id": "uuid",
  "intent": "user intent",
  "steps": [
    {
      "step_id": "uuid",
      "adapter": "bash|powershell",
      "command": "string",
      "expected_state_changes": {}
    }
  ]
}
'''
        
        payload = {
            "model": "openai/gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Intent: {intent}"}
            ],
            "temperature": 0.1
        }
        
        try:
            response = self.request(payload)
            response.raise_for_status()
            result = response.json()
            raw_content = result['choices'][0]['message']['content'].strip()
            
            return self._extract_json(raw_content)
        except Exception as e:
            raise RuntimeError(f"Proxy Connection / Generation Error: {e}")

class ResilientSemanticCompiler:
    """
    Wraps the compilation process with tenacity to handle hallucination or schema drift.
    """
    def __init__(self, client: LLMClient):
        self.client = client

    @retry(
        retry=retry_if_exception_type((ValidationError, ValueError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def compile_intent(self, intent: str, model_cls):
        raw_dict = self.client.to_ucer(intent)
        return model_cls(**raw_dict)

class MockLLMClient(LLMClient):
    """
    A mock provider for testing determinism without actual LLM latency.
    """
    def to_ucer(self, intent: str) -> dict:
        command = "echo 'default'"
        adapter = "bash"
        
        if "log" in intent.lower():
            command = "find /var/log -type f -mtime -1"
            adapter = "bash"
        elif "process" in intent.lower() and "windows" in intent.lower():
            command = "Get-Process"
            adapter = "powershell"
            
        return {
            "command_id": str(uuid.uuid4()),
            "intent": intent,
            "steps": [
                {
                    "step_id": str(uuid.uuid4()),
                    "adapter": adapter,
                    "command": command,
                    "expected_state_changes": {}
                }
            ]
        }

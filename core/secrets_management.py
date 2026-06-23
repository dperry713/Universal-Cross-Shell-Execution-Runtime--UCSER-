"""
Secrets Management for UCSER
- Integration with HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- Local encrypted storage fallback
- Rotation policies
"""

import os
import json
import logging
from typing import Dict, Optional, List
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
import base64

try:
    import hvac  # HashiCorp Vault
except ImportError:
    hvac = None

try:
    import boto3  # AWS SDK
except ImportError:
    boto3 = None

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
except ImportError:
    DefaultAzureCredential = None
    SecretClient = None

logger = logging.getLogger(__name__)


@dataclass
class Secret:
    """Secret object with metadata"""
    name: str
    value: str
    created_at: datetime
    rotated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    tags: Dict[str, str] = None
    
    def is_expired(self) -> bool:
        """Check if secret has expired"""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def needs_rotation(self, rotation_days: int = 90) -> bool:
        """Check if secret needs rotation"""
        if self.rotated_at is None:
            last_change = self.created_at
        else:
            last_change = self.rotated_at
        
        return datetime.utcnow() > last_change + timedelta(days=rotation_days)


class SecretsBackend(ABC):
    """Abstract base for secrets backends"""
    
    @abstractmethod
    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve secret by name"""
        pass
    
    @abstractmethod
    def set_secret(self, name: str, value: str, tags: Optional[Dict] = None) -> bool:
        """Store secret"""
        pass
    
    @abstractmethod
    def delete_secret(self, name: str) -> bool:
        """Delete secret"""
        pass
    
    @abstractmethod
    def list_secrets(self) -> List[str]:
        """List all secret names"""
        pass
    
    @abstractmethod
    def rotate_secret(self, name: str, new_value: str) -> bool:
        """Rotate secret to new value"""
        pass


class VaultBackend(SecretsBackend):
    """HashiCorp Vault backend"""
    
    def __init__(self, vault_addr: str, vault_token: str, mount_point: str = "secret"):
        if not hvac:
            raise ImportError("hvac library required for Vault backend")
        
        self.client = hvac.Client(url=vault_addr, token=vault_token)
        self.mount_point = mount_point
        
        # Verify connection
        try:
            self.client.is_authenticated()
            logger.info(f"Connected to Vault at {vault_addr}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Vault: {e}")
    
    def get_secret(self, name: str) -> Optional[str]:
        """Get secret from Vault"""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=name,
                mount_point=self.mount_point
            )
            return response['data']['data'].get('value')
        except Exception as e:
            logger.error(f"Failed to retrieve secret {name}: {e}")
            return None
    
    def set_secret(self, name: str, value: str, tags: Optional[Dict] = None) -> bool:
        """Store secret in Vault"""
        try:
            secret_data = {
                'value': value,
                'stored_at': datetime.utcnow().isoformat(),
            }
            if tags:
                secret_data['tags'] = tags
            
            self.client.secrets.kv.v2.create_or_update_secret(
                path=name,
                secret=secret_data,
                mount_point=self.mount_point
            )
            logger.info(f"Stored secret {name} in Vault")
            return True
        except Exception as e:
            logger.error(f"Failed to store secret {name}: {e}")
            return False
    
    def delete_secret(self, name: str) -> bool:
        """Delete secret from Vault"""
        try:
            self.client.secrets.kv.v2.delete_secret_version(
                path=name,
                mount_point=self.mount_point
            )
            logger.info(f"Deleted secret {name} from Vault")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {name}: {e}")
            return False
    
    def list_secrets(self) -> List[str]:
        """List all secret paths in Vault"""
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                mount_point=self.mount_point
            )
            return response.get('data', {}).get('keys', [])
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []
    
    def rotate_secret(self, name: str, new_value: str) -> bool:
        """Rotate secret"""
        return self.set_secret(name, new_value)


class AWSSecretsManagerBackend(SecretsBackend):
    """AWS Secrets Manager backend"""
    
    def __init__(self, region: str = "us-east-1"):
        if not boto3:
            raise ImportError("boto3 library required for AWS Secrets Manager")
        
        self.client = boto3.client('secretsmanager', region_name=region)
        logger.info(f"Connected to AWS Secrets Manager in {region}")
    
    def get_secret(self, name: str) -> Optional[str]:
        """Get secret from AWS Secrets Manager"""
        try:
            response = self.client.get_secret_value(SecretId=name)
            if 'SecretString' in response:
                return response['SecretString']
            return None
        except self.client.exceptions.ResourceNotFoundException:
            logger.error(f"Secret {name} not found in AWS Secrets Manager")
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve secret {name}: {e}")
            return None
    
    def set_secret(self, name: str, value: str, tags: Optional[Dict] = None) -> bool:
        """Store secret in AWS Secrets Manager"""
        try:
            kwargs = {
                'Name': name,
                'SecretString': value,
            }
            if tags:
                kwargs['Tags'] = [{'Key': k, 'Value': v} for k, v in tags.items()]
            
            self.client.create_secret(**kwargs)
            logger.info(f"Stored secret {name} in AWS Secrets Manager")
            return True
        except self.client.exceptions.ResourceExistsException:
            # Secret exists, update it
            self.client.update_secret(SecretId=name, SecretString=value)
            return True
        except Exception as e:
            logger.error(f"Failed to store secret {name}: {e}")
            return False
    
    def delete_secret(self, name: str) -> bool:
        """Delete secret from AWS Secrets Manager"""
        try:
            self.client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
            logger.info(f"Deleted secret {name} from AWS Secrets Manager")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {name}: {e}")
            return False
    
    def list_secrets(self) -> List[str]:
        """List all secrets in AWS Secrets Manager"""
        try:
            response = self.client.list_secrets()
            return [s['Name'] for s in response.get('SecretList', [])]
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []
    
    def rotate_secret(self, name: str, new_value: str) -> bool:
        """Rotate secret"""
        return self.set_secret(name, new_value)


class EncryptedLocalBackend(SecretsBackend):
    """Encrypted local storage (fallback)"""
    
    def __init__(self, storage_dir: str = "/var/lib/ucser/secrets"):
        from cryptography.fernet import Fernet
        
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, mode=0o700, exist_ok=True)
        
        # Generate or load encryption key
        key_path = os.path.join(storage_dir, ".key")
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(self.key)
            os.chmod(key_path, 0o600)
        
        self.cipher = Fernet(self.key)
        logger.info(f"Using encrypted local storage at {storage_dir}")
    
    def get_secret(self, name: str) -> Optional[str]:
        """Get encrypted secret from local storage"""
        try:
            secret_path = os.path.join(self.storage_dir, f"{name}.enc")
            if not os.path.exists(secret_path):
                return None
            
            with open(secret_path, 'rb') as f:
                encrypted = f.read()
            
            decrypted = self.cipher.decrypt(encrypted).decode()
            return decrypted
        except Exception as e:
            logger.error(f"Failed to retrieve secret {name}: {e}")
            return None
    
    def set_secret(self, name: str, value: str, tags: Optional[Dict] = None) -> bool:
        """Store encrypted secret locally"""
        try:
            secret_path = os.path.join(self.storage_dir, f"{name}.enc")
            encrypted = self.cipher.encrypt(value.encode())
            
            with open(secret_path, 'wb') as f:
                f.write(encrypted)
            
            os.chmod(secret_path, 0o600)
            logger.info(f"Stored encrypted secret {name} locally")
            return True
        except Exception as e:
            logger.error(f"Failed to store secret {name}: {e}")
            return False
    
    def delete_secret(self, name: str) -> bool:
        """Delete encrypted secret"""
        try:
            secret_path = os.path.join(self.storage_dir, f"{name}.enc")
            if os.path.exists(secret_path):
                os.remove(secret_path)
            logger.info(f"Deleted encrypted secret {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {name}: {e}")
            return False
    
    def list_secrets(self) -> List[str]:
        """List all stored secrets"""
        try:
            secrets = []
            for filename in os.listdir(self.storage_dir):
                if filename.endswith('.enc'):
                    secrets.append(filename[:-4])
            return secrets
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []
    
    def rotate_secret(self, name: str, new_value: str) -> bool:
        """Rotate secret"""
        return self.set_secret(name, new_value)


class SecretsManager:
    """High-level secrets management API"""
    
    def __init__(self, backend: Optional[SecretsBackend] = None):
        if backend is None:
            # Default to encrypted local storage
            backend = EncryptedLocalBackend()
        
        self.backend = backend
    
    @staticmethod
    def from_environment() -> 'SecretsManager':
        """Create SecretsManager from environment variables"""
        backend_type = os.getenv('UCSER_SECRETS_BACKEND', 'local').lower()
        
        if backend_type == 'vault':
            backend = VaultBackend(
                vault_addr=os.getenv('VAULT_ADDR', 'http://localhost:8200'),
                vault_token=os.getenv('VAULT_TOKEN'),
            )
        elif backend_type == 'aws':
            backend = AWSSecretsManagerBackend(
                region=os.getenv('AWS_REGION', 'us-east-1')
            )
        else:
            backend = EncryptedLocalBackend(
                storage_dir=os.getenv('UCSER_SECRETS_DIR', '/var/lib/ucser/secrets')
            )
        
        return SecretsManager(backend)
    
    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve secret"""
        value = self.backend.get_secret(name)
        if value is None:
            logger.warning(f"Secret {name} not found")
        return value
    
    def set_secret(self, name: str, value: str, tags: Optional[Dict] = None) -> bool:
        """Store secret"""
        return self.backend.set_secret(name, value, tags)
    
    def delete_secret(self, name: str) -> bool:
        """Delete secret"""
        return self.backend.delete_secret(name)
    
    def get_required_secret(self, name: str) -> str:
        """Get secret, raise error if not found"""
        value = self.get_secret(name)
        if value is None:
            raise ValueError(f"Required secret {name} not found")
        return value


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example usage
    mgr = SecretsManager.from_environment()
    
    # Store secret
    mgr.set_secret("db_password", "super_secret_123", tags={"env": "prod"})
    
    # Retrieve secret
    pwd = mgr.get_secret("db_password")
    print(f"Password: {pwd}")
    
    # List secrets
    all_secrets = mgr.backend.list_secrets()
    print(f"Secrets: {all_secrets}")

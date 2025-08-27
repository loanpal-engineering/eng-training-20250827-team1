import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SSNEncryption:
    def __init__(self):
        encryption_key = os.environ.get('SSN_ENCRYPTION_KEY')
        if not encryption_key:
            encryption_key = self._generate_key_from_password()
        else:
            encryption_key = encryption_key.encode()
        
        self.cipher = Fernet(encryption_key)
    
    def _generate_key_from_password(self):
        password = os.environ.get('DATABASE_PASSWORD', 'default-password-change-me').encode()
        salt = b'vulnleap-ssn-salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_ssn(self, ssn):
        if not ssn:
            return None
        ssn_str = str(ssn).replace('-', '')
        encrypted = self.cipher.encrypt(ssn_str.encode())
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt_ssn(self, encrypted_ssn):
        if not encrypted_ssn:
            return None
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_ssn.encode('utf-8'))
            decrypted = self.cipher.decrypt(encrypted_data)
            return decrypted.decode('utf-8')
        except Exception:
            return encrypted_ssn


ssn_encryptor = SSNEncryption()
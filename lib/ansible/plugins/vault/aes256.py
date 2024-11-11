# (c) The Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

DOCUMENTATION = """
    name: aes256
    version_added: "2.4"
    short_description: Legacy AES256 with PBKDF2HMAC key derivation and double hexlify byte shield.
    requirements:
        - cryptography (python)
    options:
        salt:
            description: 
                - Encryption salt to use, if not set it will be random.
                - This is mostly here for having a reproducible result when testing and should not be set in production use
            type: str
            version_added: '2.15'
            ini:
            - {key: salt, section: aes256_vault}
            - {key: vault_encrypt_salt, section: defaults}
            env: 
            - name: ANSIBLE_VAULT_AES256_SALT
            - name: ANSIBLE_VAULT_ENCRYPT_SALT
        iterations:    
            description: 
                - Number of passes to do for deriving keys, the higher the number the more secure, but also the more it costs and the longer it takes.
            type: int
            default: 600000
            ini:
            - key: iterations
              section: aes256_vault
            env:
            - name: ANSIBLE_VAULT_AES256_ITERATIONS
        key_length:    
            description: Lentgh of derived key
            type: int
            default: 32
"""

import os
import json
import typing as t

from binascii import hexlify, unhexlify
try:
    from cryptography.exceptions import InvalidSignature
    # hazmat can cause import errors, handled by caller
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher as C_Cipher, algorithms, modes
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPT_IMPORT_ERROR = None
except Exception as e:
    # not using importerror as crypto libraries frequently issue different exceptions, specially under FIPS
    CRYPT_IMPORT_ERROR = e

from ansible.errors import AnsibleError
from ansible.utils.display import Display
from ansible.module_utils.basic import missing_required_lib


from ansible.parsing.vault import VaultSecret
from . import VaultMethodBase, VaultSecretError


class VaultMethod(VaultMethodBase):
    """Vault implementation using AES-CTR with an HMAC-SHA256 authentication code. Keys are derived using PBKDF2."""

    _V1_DEFAULTS = {'iterations': 10_000, 'key_length': 32}
    def __init__(self):
        if CRYPT_IMPORT_ERROR is not None:
            VaultMethodBase._import_error('cryptography', CRYPT_IMPORT_ERROR)
        self.CRYPTOGRAPHY_BACKEND = default_backend()

    @VaultMethodBase.lru_cache()
    def _generate_keys_and_iv(self, secret: bytes, salt: bytes) -> tuple[bytes, bytes, bytes]:

        # AES is a 128-bit block cipher, so we used a 32 byte key and 16 byte IVs and counter nonces
        key_length = self.get_options('key_lengh')
        iv_length = algorithms.AES.block_size // 8

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length * 2 + iv_length,
            salt=salt,
            iterations=self.get_option('iterations'),
            backend=self.CRYPTOGRAPHY_BACKEND,
        )

        derived_key = kdf.derive(secret)

        key1 = derived_key[:key_length]
        key2 = derived_key[key_length:key_length * 2]
        iv = derived_key[key_length * 2:]

        return key1, key2, iv

    def encrypt(self, plaintext: bytes, secret: VaultSecret, options: dict[str, t.Any]) -> str:
        Display().warning("Encryption with the AES256 method should only be used for backwards compatibility with older versions of Ansible.")

        self.set_options(direct=options)

        salt = self.get_option('salt')
        if salt:
            salt = salt.encode(errors='surrogateescape')
        else:
            salt = os.urandom(32)

        key1, key2, iv = self._generate_keys_and_iv(secret.bytes, salt)

        cipher = C_Cipher(algorithms.AES(key1), modes.CTR(iv), self.CRYPTOGRAPHY_BACKEND)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        ciphertext = encryptor.update(padder.update(plaintext) + padder.finalize()) + encryptor.finalize()

        hmac = HMAC(key2, hashes.SHA256(), self.CRYPTOGRAPHY_BACKEND)
        hmac.update(ciphertext)
        signature = hmac.finalize()

        # save params for decryption, except salt which goes in header
        options = self.get_options()
        del options['salt']
        params = json.dump(options)

        # redundant double hexlify cannot be removed as it is backwards incompatible
        return hexlify(b'\n'.join(map(hexlify, (salt, signature, ciphertext, params)))).decode()

    @classmethod
    def decrypt(self, vaulttext: str, secret: VaultSecret) -> bytes:

        salt, signature, ciphertext, params = map(unhexlify, unhexlify(vaulttext).split(b'\n', 3))

        if params:
            options = json.loads(params)
        else:
            # old vaults did not save params, set iterations to compatible defaults
            options = VaultMethod._V1_DEFAULTS
        self.set_options(direct=options)

        key1, key2, iv = self._generate_keys_and_iv(secret.bytes, salt)

        hmac = HMAC(key2, hashes.SHA256(), self.CRYPTOGRAPHY_BACKEND)
        hmac.update(ciphertext)

        try:
            hmac.verify(signature)
        except InvalidSignature as ex:
            raise VaultSecretError() from ex

        cipher = C_Cipher(algorithms.AES(key1), modes.CTR(iv), self.CRYPTOGRAPHY_BACKEND)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        return unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()

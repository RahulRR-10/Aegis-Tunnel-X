import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _validate_key(key: bytes) -> None:
	if len(key) != 32:
		raise ValueError("AES-256-GCM requires a 32-byte key")


def encrypt(plaintext: bytes, key: bytes) -> bytes:
	_validate_key(key)
	aesgcm = AESGCM(key)
	nonce = os.urandom(12)
	ciphertext = aesgcm.encrypt(nonce, plaintext, None)
	return nonce + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
	_validate_key(key)
	if len(data) < 12:
		raise ValueError("Encrypted packet too short")

	aesgcm = AESGCM(key)
	nonce = data[:12]
	ciphertext = data[12:]
	return aesgcm.decrypt(nonce, ciphertext, None)

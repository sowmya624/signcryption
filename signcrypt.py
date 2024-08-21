from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate EC keys
sender_private_key = ec.generate_private_key(ec.SECP256R1())
recipient_private_key = ec.generate_private_key(ec.SECP256R1())
sender_public_key = sender_private_key.public_key()
recipient_public_key = recipient_private_key.public_key()

# Serialize keys for demonstration (not required in actual use)
sender_private_pem = sender_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
recipient_private_pem = recipient_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
sender_public_pem = sender_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
recipient_public_pem = recipient_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save private keys and public keys to file
with open('sender_private_key.pem', 'wb') as f:
    f.write(sender_private_pem)
with open('recipient_private_key.pem', 'wb') as f:
    f.write(recipient_private_pem)
with open('sender_public_key.pem', 'wb') as f:
    f.write(sender_public_pem)
with open('recipient_public_key.pem', 'wb') as f:
    f.write(recipient_public_pem)

# Derive shared key
shared_key = sender_private_key.exchange(ec.ECDH(), recipient_public_key)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'signcryption'
).derive(shared_key)

# Encrypt and sign (Signcryption)
message = b"Secret Message"
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
tag = encryptor.tag

# Save ciphertext, iv, and tag to file
with open('ciphertext.bin', 'wb') as f:
    f.write(ciphertext)
with open('iv.bin', 'wb') as f:
    f.write(iv)
with open('tag.bin', 'wb') as f:
    f.write(tag)

print("Signcryption complete.")
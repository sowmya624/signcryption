from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load recipient's private key and sender's public key from files
with open('recipient_private_key.pem', 'rb') as f:
    recipient_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )
with open('sender_public_key.pem', 'rb') as f:
    sender_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Load ciphertext, IV, and tag from files
with open('ciphertext.bin', 'rb') as f:
    ciphertext = f.read()
with open('iv.bin', 'rb') as f:
    iv = f.read()
with open('tag.bin', 'rb') as f:
    tag = f.read()

# Derive the shared key using recipient's private key and sender's public key
shared_key = recipient_private_key.exchange(ec.ECDH(), sender_public_key)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'signcryption'
).derive(shared_key)

# Decrypt and verify (unsigncryption)
cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag))
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

print("Decrypted message:", decrypted_message.decode())
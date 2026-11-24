import base64
import hashlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 200000


def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s.encode())


def _key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode())


def sha256(data):
    text = data.get("text", "")
    other = data.get("compare")
    digest = hashlib.sha256(text.encode()).hexdigest()
    out = {"digest": digest, "bits": 256, "input_bytes": len(text.encode())}
    if other is not None and other != "":
        d2 = hashlib.sha256(other.encode()).hexdigest()
        diff = bin(int(digest, 16) ^ int(d2, 16)).count("1")
        out.update(compare_digest=d2, bits_changed=diff, percent_changed=round(diff / 256 * 100, 1))
    return out


def aes_encrypt(data):
    text, password = data.get("text", ""), data.get("password", "")
    if not password:
        raise ValueError("Password is required")
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(password, salt)).encrypt(nonce, text.encode(), None)
    return {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ct),
        "algorithm": "AES-256-GCM, key from PBKDF2-HMAC-SHA256 (%d iterations)" % ITERATIONS,
        "package": "%s.%s.%s" % (b64e(salt), b64e(nonce), b64e(ct)),
    }


def aes_decrypt(data):
    password = data.get("password", "")
    parts = (data.get("package") or "").strip().split(".")
    if len(parts) != 3:
        raise ValueError("Package must look like salt.nonce.ciphertext (three base64 parts)")
    try:
        salt, nonce, ct = (b64d(x) for x in parts)
        pt = AESGCM(_key(password, salt)).decrypt(nonce, ct, None)
    except InvalidTag:
        return {"ok": False, "message": "Authentication failed: wrong password or the ciphertext was modified (integrity check)."}
    return {"ok": True, "plaintext": pt.decode(errors="replace"), "message": "Decrypted and integrity verified."}


def rsa_generate(data):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"private_pem": priv, "public_pem": pub, "bits": 2048}


def _pub(pem):
    return serialization.load_pem_public_key(pem.encode())


def _priv(pem):
    return serialization.load_pem_private_key(pem.encode(), password=None)


_OAEP = lambda: padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = lambda: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def rsa_encrypt(data):
    text = data.get("text", "").encode()
    if len(text) > 190:
        raise ValueError("RSA-2048 OAEP can encrypt at most 190 bytes directly")
    return {"ciphertext": b64e(_pub(data["public_pem"]).encrypt(text, _OAEP())), "padding": "OAEP with SHA-256"}


def rsa_decrypt(data):
    try:
        pt = _priv(data["private_pem"]).decrypt(b64d(data.get("ciphertext", "").strip()), _OAEP())
    except Exception:
        return {"ok": False, "message": "Decryption failed: wrong private key or damaged ciphertext."}
    return {"ok": True, "plaintext": pt.decode(errors="replace"), "message": "Decrypted with the private key."}


def sign(data):
    sig = _priv(data["private_pem"]).sign(data.get("text", "").encode(), _PSS(), hashes.SHA256())
    return {"signature": b64e(sig), "scheme": "RSA-PSS with SHA-256"}


def verify(data):
    try:
        _pub(data["public_pem"]).verify(b64d(data.get("signature", "").strip()), data.get("text", "").encode(), _PSS(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        return {"ok": False, "message": "Signature is INVALID: the message or the signature was altered, or the key does not match."}
    return {"ok": True, "message": "Signature is VALID: the message is authentic and unchanged."}


OPS = {
    "sha256": sha256,
    "aes_encrypt": aes_encrypt,
    "aes_decrypt": aes_decrypt,
    "rsa_generate": rsa_generate,
    "rsa_encrypt": rsa_encrypt,
    "rsa_decrypt": rsa_decrypt,
    "sign": sign,
    "verify": verify,
}


def run(op, data):
    fn = OPS.get(op)
    if not fn:
        raise ValueError("Unknown operation")
    return fn(data)

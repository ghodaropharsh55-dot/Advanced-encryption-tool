

import os
import argparse
import getpass
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"AESGCM1"           
SALT_LEN = 16                
NONCE_LEN = 12               
KDF_ITERS = 200_000          
KEY_LEN = 32                 

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=KDF_ITERS)
    return kdf.derive(password)

def write_encrypted(out_path: str, salt: bytes, nonce: bytes, ciphertext: bytes) -> None:
    with open(out_path, "wb") as f:
       
        f.write(MAGIC + salt + nonce + ciphertext)

def read_encrypted(in_path: str) -> Tuple[bytes, bytes, bytes]:
    with open(in_path, "rb") as f:
        blob = f.read()
    if len(blob) < len(MAGIC) + SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Invalid file: too short.")
    if not constant_time.bytes_eq(blob[:len(MAGIC)], MAGIC):
        raise ValueError("Invalid file: magic header mismatch.")
    salt = blob[len(MAGIC):len(MAGIC)+SALT_LEN]
    nonce = blob[len(MAGIC)+SALT_LEN:len(MAGIC)+SALT_LEN+NONCE_LEN]
    ciphertext = blob[len(MAGIC)+SALT_LEN+NONCE_LEN:]
    return salt, nonce, ciphertext

def encrypt_file(in_path: str, out_path: str, password: str) -> None:
    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"Input not found: {in_path}")
    salt = os.urandom(SALT_LEN)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    with open(in_path, "rb") as f:
        plaintext = f.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    write_encrypted(out_path, salt, nonce, ciphertext)

def decrypt_file(in_path: str, out_path: str, password: str) -> None:
    salt, nonce, ciphertext = read_encrypted(in_path)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)  # raises InvalidTag if wrong
    with open(out_path, "wb") as f:
        f.write(plaintext)

def main():
    parser = argparse.ArgumentParser(description="Advanced Encryption Tool (AES-256-GCM)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("-i", "--input", required=True, help="Input file path")
    p_enc.add_argument("-o", "--output", help="Output file path (default: <input>.enc)")

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("-i", "--input", required=True, help="Encrypted file path (.enc)")
    p_dec.add_argument("-o", "--output", help="Decrypted output file path")

    args = parser.parse_args()

    if args.cmd == "encrypt":
        out = args.output or (args.input + ".enc")
        pwd = getpass.getpass("Set password: ")
        confirm = getpass.getpass("Confirm password: ")
        if pwd != confirm:
            raise SystemExit("Passwords do not match.")
        encrypt_file(args.input, out, pwd)
        print(f"[OK] Encrypted → {out}")

    elif args.cmd == "decrypt":
        out = args.output
        if not out:
            # strip .enc if present; else append .dec
            out = args.input[:-4] if args.input.lower().endswith(".enc") else (args.input + ".dec")
        pwd = getpass.getpass("Enter password: ")
        try:
            decrypt_file(args.input, out, pwd)
            print(f"[OK] Decrypted → {out}")
        except Exception as e:
            raise SystemExit(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()

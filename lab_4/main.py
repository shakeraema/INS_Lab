import sys, time, os
from pathlib import Path
from crypto_utils import (
    aes_encrypt_file, aes_decrypt_file,
    rsa_generate_keys, rsa_encrypt_file, rsa_decrypt_file,
    rsa_sign_file, rsa_verify_file,
    sha256_file
)

BASE = Path(__file__).parent
KEYS = BASE / "keys"; KEYS.mkdir(exist_ok=True)
OUT  = BASE / "out";  OUT.mkdir(exist_ok=True)

def menu():
    print("""
Lab 4 — Crypto CLI
1) AES encrypt (ECB/CFB, 128/256)
2) AES decrypt
3) RSA generate keypair
4) RSA encrypt
5) RSA decrypt
6) RSA sign
7) RSA verify
8) SHA-256 of file
9) Quit
""")

def timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    dt = (time.perf_counter() - t0)
    print(f"[Time] {fn.__name__}: {dt:.6f} s")
    return result, dt

def main():
    while True:
        menu()
        choice = input("Select option: ").strip()
        if choice == "1":
            infile = input("File to encrypt: ").strip()
            mode   = input("Mode [ECB/CFB]: ").strip().upper()
            bits   = int(input("Key length [128/256]: ").strip())
            keyfile = KEYS / f"aes{bits}.key"
            ivfile  = KEYS / "iv.hex"
            aes_encrypt_file(infile, OUT / f"{Path(infile).name}.{mode.lower()}.enc", mode, bits, keyfile, ivfile)
        elif choice == "2":
            encfile = input("Encrypted file: ").strip()
            mode    = input("Mode used [ECB/CFB]: ").strip().upper()
            bits    = int(input("Key length used [128/256]: ").strip())
            keyfile = KEYS / f"aes{bits}.key"
            ivfile  = KEYS / "iv.hex"
            aes_decrypt_file(encfile, OUT / f"{Path(encfile).stem}.dec", mode, bits, keyfile, ivfile)
        elif choice == "3":
            bits = int(input("RSA bits [2048/3072/4096]: ").strip())
            rsa_generate_keys(KEYS / "rsa_priv.pem", KEYS / "rsa_pub.pem", bits)
        elif choice == "4":
            infile = input("File to RSA-encrypt: ").strip()
            rsa_encrypt_file(infile, OUT / f"{Path(infile).name}.rsa.enc", KEYS / "rsa_pub.pem")
        elif choice == "5":
            encfile = input("RSA-encrypted file: ").strip()
            rsa_decrypt_file(encfile, OUT / f"{Path(encfile).stem}.rsa.dec", KEYS / "rsa_priv.pem")
        elif choice == "6":
            infile = input("File to sign: ").strip()
            rsa_sign_file(infile, OUT / f"{Path(infile).name}.sig", KEYS / "rsa_priv.pem")
        elif choice == "7":
            infile = input("File to verify: ").strip()
            sig    = input("Signature file: ").strip()
            ok = rsa_verify_file(infile, sig, KEYS / "rsa_pub.pem")
            print("Verified OK" if ok else "Verification FAILED")
        elif choice == "8":
            infile = input("File to hash: ").strip()
            print("SHA-256:", sha256_file(infile))
        elif choice == "9":
            print("Quitting!"); break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

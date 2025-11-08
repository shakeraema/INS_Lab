import time, csv, os, statistics
from pathlib import Path
from Crypto.Random import get_random_bytes
from crypto_utils import (
    aes_encrypt_file, aes_decrypt_file,
    rsa_generate_keys, rsa_encrypt_file, rsa_decrypt_file
)

BASE = Path(__file__).parent
KEYS = BASE / "keys"; KEYS.mkdir(exist_ok=True)
OUT  = BASE / "out";  OUT.mkdir(exist_ok=True)
REPORT = BASE / "report"; REPORT.mkdir(exist_ok=True)
DATA = REPORT / "timings.csv"

PT_SMALL = BASE / "msg.txt"   # small file ok for RSA (short content!)
PT_BIG   = BASE / "big.bin"   # a bigger file for AES throughput

def ensure_inputs():
    if not PT_SMALL.exists():
        PT_SMALL.write_text("Hello I am Shakera Jannat Ema.")
    if not PT_BIG.exists():
        # ~1 MB random data for AES tests
        PT_BIG.write_bytes(get_random_bytes(1_000_000))

def tsec(fn, *args, **kwargs) -> float:
    t0 = time.perf_counter()
    fn(*args, **kwargs)
    return time.perf_counter() - t0

def run_aes_trials(n_trials=5):
    rows = []
    for mode in ("ECB", "CFB"):
        for bits in (128, 256):
            # choose file: big for AES to see a real difference
            infile = PT_BIG
            encfile = OUT / f"{infile.name}.{mode.lower()}.{bits}.enc"
            decfile = OUT / f"{infile.name}.{mode.lower()}.{bits}.dec"
            enc_times, dec_times = [], []

            for _ in range(n_trials):
                enc_times.append(tsec(aes_encrypt_file, infile, encfile, mode, bits, KEYS / f"aes{bits}.key", KEYS / "iv.hex"))
                dec_times.append(tsec(aes_decrypt_file, encfile, decfile, mode, bits, KEYS / f"aes{bits}.key", KEYS / "iv.hex"))

            rows.append(["AES", mode, bits, "encrypt", n_trials, statistics.mean(enc_times)])
            rows.append(["AES", mode, bits, "decrypt", n_trials, statistics.mean(dec_times)])
    return rows

def run_rsa_trials(n_trials=5):
    rows = []
    # Use real sizes for RSA
    for bits in (1024, 2048, 3072, 4096):
        # keygen timing (optional but useful)
        kg_times = []
        for _ in range(n_trials):
            priv = KEYS / "rsa_priv.pem"
            pub  = KEYS / "rsa_pub.pem"
            # regenerate each trial to time fairly
            kg_times.append(tsec(rsa_generate_keys, priv, pub, bits))
        rows.append(["RSA", "OAEP-SHA256", bits, "keygen", n_trials, statistics.mean(kg_times)])

        # encrypt/decrypt timing (small file!)
        enc_times, dec_times = [], []
        encfile = OUT / f"{PT_SMALL.name}.rsa{bits}.enc"
        decfile = OUT / f"{PT_SMALL.name}.rsa{bits}.dec"
        for _ in range(n_trials):
            enc_times.append(tsec(rsa_encrypt_file, PT_SMALL, encfile, KEYS / "rsa_pub.pem"))
            dec_times.append(tsec(rsa_decrypt_file, encfile, decfile, KEYS / "rsa_priv.pem"))

        rows.append(["RSA", "OAEP-SHA256", bits, "encrypt", n_trials, statistics.mean(enc_times)])
        rows.append(["RSA", "OAEP-SHA256", bits, "decrypt", n_trials, statistics.mean(dec_times)])
    return rows

def main():
    ensure_inputs()
    rows = [["algo","mode_or_scheme","bits","operation","trials","avg_seconds"]]
    rows += run_aes_trials(n_trials=5)
    rows += run_rsa_trials(n_trials=5)

    with open(DATA, "w", newline="") as f:
        w = csv.writer(f)
        w.writerows(rows)
    print(f"Wrote: {DATA}")

if __name__ == "__main__":
    main()

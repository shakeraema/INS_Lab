from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def _read_hex(path: Path, nbytes: int = None):
    path = Path(path)
    if not path.exists():
        # if missing, create fresh hex of required size
        if nbytes is None:
            raise ValueError("Need nbytes to create new hex file")
        data = get_random_bytes(nbytes).hex()
        path.write_text(data)
    return bytes.fromhex(path.read_text().strip())

def aes_encrypt_file(infile, outfile, mode, bits, keyfile, ivfile):
    infile, outfile = Path(infile), Path(outfile)
    key = _read_hex(keyfile, 16 if bits == 128 else 32)
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        iv = None
    elif mode == "CFB":
        iv = _read_hex(ivfile, 16)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    else:
        raise ValueError("Mode must be ECB or CFB")
    pt = infile.read_bytes()
    ct = cipher.encrypt(pad(pt, AES.block_size) if mode == "ECB" else pt)
    outfile.write_bytes(ct)
    print(f"[AES-{bits}-{mode}] wrote: {outfile}")

def aes_decrypt_file(encfile, outfile, mode, bits, keyfile, ivfile):
    encfile, outfile = Path(encfile), Path(outfile)
    key = _read_hex(keyfile)
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        iv = None
    elif mode == "CFB":
        iv = _read_hex(ivfile)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    else:
        raise ValueError("Mode must be ECB or CFB")
    ct = encfile.read_bytes()
    pt = cipher.decrypt(ct)
    if mode == "ECB":
        pt = unpad(pt, AES.block_size)
    outfile.write_bytes(pt)
    print(f"[AES-{bits}-{mode}] wrote: {outfile}")

def rsa_generate_keys(priv_path, pub_path, bits=2048):
    key = RSA.generate(bits)
    priv_pem = key.export_key()
    pub_pem  = key.publickey().export_key()
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    print(f"[RSA-{bits}] keys written to {priv_path} & {pub_path}")

def rsa_encrypt_file(infile, outfile, pub_path):
    pub = RSA.import_key(Path(pub_path).read_bytes())
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    data = Path(infile).read_bytes()
    # OAEP can only encrypt up to k-2hLen-2 bytes; use small files or hybrid (AES+RSA) for bigger data.
    ct = cipher.encrypt(data)
    Path(outfile).write_bytes(ct)
    print(f"[RSA-OAEP] wrote: {outfile}")

def rsa_decrypt_file(encfile, outfile, priv_path):
    priv = RSA.import_key(Path(priv_path).read_bytes())
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    ct = Path(encfile).read_bytes()
    pt = cipher.decrypt(ct)
    Path(outfile).write_bytes(pt)
    print(f"[RSA-OAEP] wrote: {outfile}")

def rsa_sign_file(infile, sigfile, priv_path):
    priv = RSA.import_key(Path(priv_path).read_bytes())
    h = SHA256.new(Path(infile).read_bytes())
    sig = pkcs1_15.new(priv).sign(h)
    Path(sigfile).write_bytes(sig)
    print(f"[RSA-Sign] wrote: {sigfile}")

def rsa_verify_file(infile, sigfile, pub_path) -> bool:
    pub = RSA.import_key(Path(pub_path).read_bytes())
    h = SHA256.new(Path(infile).read_bytes())
    sig = Path(sigfile).read_bytes()
    try:
        pkcs1_15.new(pub).verify(h, sig)
        return True
    except Exception:
        return False

def sha256_file(infile) -> str:
    return SHA256.new(Path(infile).read_bytes()).hexdigest()

# substitution_lab.py
# Checkpoint-2: Solve monoalphabetic substitution ciphers.
# Works on macOS in VS Code. No Ubuntu needed.
# This script is ORIGINAL code (no copied snippets). If you later download a quadgram file,
# remember to include that link in your report.

import math
import os
import random
import string
from collections import Counter

# --------------------------
# 1) INPUT: the two ciphers
# --------------------------
CIPHER1 = (
    "af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eao-"
    "-wvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg "
    "du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm "
    "epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvc-"
    "-pfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnir--ceiki tdvng pc niprc kiopaf dfi "
    "mddg oafg cepc tdvng qdfcafvi cei kiripkqe"
)

CIPHER2 = (
    "aceah toz puvg vcdl omj puvg yudqecov, omj loj auum klu thmjuv hs klu zlcvu shv "
    "zcbkg guovz, upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm. klu "
    "vcdluz lu loj avhqnlk aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumj, omj ck toz "
    "yhyqeoveg auecupuj, tlokupuv klu hej sher wcnlk zog, klok klu lcee ok aon umj toz sqee hs "
    "kqmmuez zkqssuj tckl kvuozqvu. omj cs klok toz mhk umhqnl shv sowu, kluvu toz oezh lcz "
    "yvhehmnuj pcnhqv kh wovpue ok. kcwu thvu hm, aqk ck zuuwuj kh lopu eckkeu ussudk hm "
    "wv. aonncmz. ok mcmukg lu toz wqdl klu zowu oz ok scskg. ok mcmukg-mcmu klug aunom kh "
    "doee lcw tuee-yvuzuvpuj; aqk qmdlomnuj thqej lopu auum muovuv klu wovr. kluvu tuvu zhwu "
    "klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn; ck zuuwuj qmsocv klok"
)

ALPH = string.ascii_lowercase
ETAOIN = "etaoinshrdlcumwfgypbvkjxqz"  # common English frequency order

# --------------------------
# 2) Helpers
# --------------------------
def clean_text(s: str) -> str:
    """Lowercase and keep only letters and spaces."""
    return "".join(ch for ch in s.lower() if ch.isalpha() or ch.isspace())

def letter_freq(s: str) -> Counter:
    """Count letter frequencies (letters only)."""
    return Counter(ch for ch in s if ch in ALPH)

def build_initial_key(cipher: str) -> dict:
    """
    Map most-frequent cipher letters to most-frequent English letters (ETAOIN).
    Returns a dict like {'x':'e', 'q':'t', ...}.
    """
    cnt = letter_freq(cipher)
    # rank cipher letters by frequency
    most = [p[0] for p in cnt.most_common()]
    # append any letters that never appeared so every letter maps to something
    for ch in ALPH:
        if ch not in most:
            most.append(ch)
    mapping = {}
    for i, cch in enumerate(most[:26]):
        mapping[cch] = ETAOIN[i]
    return mapping

def apply_mapping(text: str, mapping: dict) -> str:
    """Apply a letter-to-letter mapping; keep spaces and non-letters unchanged."""
    out = []
    for ch in text:
        if ch in ALPH:
            out.append(mapping.get(ch, ch))
        else:
            out.append(ch)
    return "".join(out)

# --------------------------
# 3) Scoring models
# --------------------------
def load_quadgram_model(fname="english_quadgrams.txt"):
    """
    Optional: if a file named english_quadgrams.txt is in the same folder,
    load it and return (log_prob_dict, floor_log10).
    File format: each line 'ABCD 1234'
    """
    if not os.path.exists(fname):
        return None
    total = 0
    counts = {}
    with open(fname, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2 and len(parts[0]) == 4:
                quad = parts[0].lower()
                if all(c in ALPH for c in quad):
                    n = int(parts[1])
                    counts[quad] = counts.get(quad, 0) + n
                    total += n
    # convert to log10 probabilities
    logp = {}
    for q, n in counts.items():
        logp[q] = math.log10(n / total)
    floor = math.log10(0.01 / total)  # tiny floor for unseen n-grams
    return logp, floor

def score_text_quadgrams(text: str, model):
    """Higher is better."""
    if model is None:
        return None  # signal to use fallback
    logp, floor = model
    s = 0.0
    # use only letters for scoring
    t = "".join(ch for ch in text if ch in ALPH)
    for i in range(len(t) - 3):
        q = t[i : i + 4]
        s += logp.get(q, floor)
    return s

def score_text_monogram_chisq(text: str):
    """
    Fallback score if quadgrams not available.
    Chi-square against rough English letter frequencies.
    We NEGATE chi-square so higher is better (smaller chisq → better).
    """
    EN = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
        's': 6.3,  'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
        'u': 2.8,  'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
        'p': 1.9,  'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.2, 'x': 0.2,
        'q': 0.1,  'z': 0.1
    }
    t = "".join(ch for ch in text if ch in ALPH)
    N = max(1, len(t))
    cnt = Counter(t)
    chisq = 0.0
    for ch in ALPH:
        obs = 100.0 * cnt[ch] / N
        exp = EN.get(ch, 0.1)
        chisq += (obs - exp) ** 2 / (exp + 1e-9)
    return -chisq

def score_text(text: str, quad_model):
    s = score_text_quadgrams(text, quad_model)
    if s is not None:
        return s
    return score_text_monogram_chisq(text)

# --------------------------
# 4) Hill-climbing refinement
# --------------------------
def random_key_from_mapping(initial_map: dict) -> str:
    """
    Convert a partial mapping dict into a 26-letter key string K
    where K[i] = plaintext letter mapped from ALPH[i].
    Fill any missing with a random permutation (keeps search diverse).
    """
    # start with identity mapping
    key = list(ALPH)
    # initial_map maps cipher->plain; we want key[cipher_index] = plain_letter
    for ciph, plain in initial_map.items():
        idx = ALPH.index(ciph)
        key[idx] = plain
    # Ensure it's a permutation: if duplicates exist, fix by shuffling the rest
    used = set(key)
    # letters missing on plaintext side:
    missing_plain = [ch for ch in ALPH if ch not in used]
    # positions that still duplicate (i.e., not a true permutation)
    # simple repair: for any duplicated position, assign from missing_plain
    seen = set()
    for i in range(26):
        if key[i] in seen:
            key[i] = None
        else:
            seen.add(key[i])
    for i in range(26):
        if key[i] is None:
            key[i] = missing_plain.pop(0)
    return "".join(key)

def key_to_mapping(key: str) -> dict:
    """Turn a 26-letter key into dict cipher->plain."""
    return {ALPH[i]: key[i] for i in range(26)}

def swap_two(key: str) -> str:
    """Swap two positions in the key (cipher-side swap of their plaintext assignments)."""
    i, j = random.sample(range(26), 2)
    k = list(key)
    k[i], k[j] = k[j], k[i]
    return "".join(k)

def hill_climb(cipher: str, initial_map: dict, quad_model, seconds=10):
    """
    Simple hill-climb: start from initial key; repeatedly try random swaps,
    keep the swap if score improves. Stop after a while.
    """
    import time
    start = time.time()
    best_key = random_key_from_mapping(initial_map)
    best_map = key_to_mapping(best_key)
    best_plain = apply_mapping(cipher, best_map)
    best_score = score_text(best_plain, quad_model)

    cur_key, cur_plain, cur_score = best_key, best_plain, best_score
    no_improve = 0

    while time.time() - start < seconds:
        cand_key = swap_two(cur_key)
        cand_map = key_to_mapping(cand_key)
        cand_plain = apply_mapping(cipher, cand_map)
        cand_score = score_text(cand_plain, quad_model)
        if cand_score > cur_score:
            cur_key, cur_plain, cur_score = cand_key, cand_plain, cand_score
            no_improve = 0
            if cur_score > best_score:
                best_key, best_plain, best_score = cur_key, cur_plain, cur_score
        else:
            no_improve += 1
            # occasional random restarts help escape local maxima
            if no_improve > 2000:
                cur_key = random_key_from_mapping(initial_map)
                cur_plain = apply_mapping(cipher, key_to_mapping(cur_key))
                cur_score = score_text(cur_plain, quad_model)
                no_improve = 0

    return best_plain, best_key, best_score

# --------------------------
# 5) Pretty printing helpers
# --------------------------
def show_top_freq(cipher: str, top=10):
    cnt = letter_freq(cipher)
    print("\nTop letter frequencies:")
    for ch, n in cnt.most_common(top):
        print(f"  {ch}: {n}")

def show_partial(cipher: str, mapping: dict, head=250):
    """
    Show a partially decoded head of the text.
    Unmapped letters are shown as '_' to help you visually spot patterns.
    """
    out = []
    for ch in cipher:
        if ch in ALPH:
            out.append(mapping.get(ch, "_"))
        else:
            out.append(ch)
    s = "".join(out)
    print("\nPartial (first ~{} chars):".format(head))
    print(s[:head] + ("..." if len(s) > head else ""))

# --------------------------
# 6) Run both ciphers
# --------------------------
def solve_cipher(name, cipher):
    print("\n" + "="*70)
    print(f"{name}: length = {len(cipher)} characters")
    print("="*70)

    clean = clean_text(cipher)
    show_top_freq(clean, top=10)

    # Initial mapping by frequency
    init_map = build_initial_key(clean)
    show_partial(clean, init_map, head=300)

    # Try to improve with hill-climbing (uses quadgrams if file exists)
    quad_model = load_quadgram_model()  # put english_quadgrams.txt here to use it
    print("\nRefining mapping... (hill-climb ~10s)")
    best_plain, best_key, best_score = hill_climb(clean, init_map, quad_model, seconds=10)

    print("\nBest key (cipher->plain) as 26 letters (index a..z):")
    print(best_key)
    print("\nDecrypted text (first ~500 chars):")
    print(best_plain[:500] + ("..." if len(best_plain) > 500 else ""))

    # If you want the whole plaintext printed:
    # print("\nFULL DECRYPTION:\n")
    # print(best_plain)

if __name__ == "__main__":
    solve_cipher("Cipher-1", CIPHER1)
    solve_cipher("Cipher-2", CIPHER2)

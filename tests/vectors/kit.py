"""Independent vectors for the 12-word kit (src/kit).

diseno-vinculacion.md §2.3 and §26.2 (VI-20), Recuperacion/diseno.md §3.1-§3.2:

    E   = 120 bits (15 bytes)
    C   = first 12 bits of SHA-256("trino/kit/v1/check" || E)
    kit = E || C = 132 bits = 12 indices of 11 bits, most significant first
    K         = Argon2id(E, salt = "trino/kit/v1", 64 MiB, t = 3, p = 1, 32 bytes)
    k_reserva = HKDF-SHA256(K, no salt, info = "trino/kit/v1/reserve", 32)
    h_check   = HKDF-SHA256(K, no salt, info = "trino/kit/v1/check-local", 32)

The word lists are BIP-39's Spanish, Portuguese and English lists, read from
src/kit/wordlists. Python's standard library builds the words; OpenSSL
(through Python's `cryptography`) computes Argon2id and HKDF.

The two "ambiguous" cases search for 12 words (whole, or four-letter prefixes
that are no word) that name words in both the Spanish and the English list
and pass the check in both, so the language cannot be told from them alone.
The searches are deterministic and take about a minute.

    python -I -X utf8 tests/vectors/kit.py > tests/vectors/kit.json
"""

import hashlib
import itertools
import json
import pathlib
import sys
import unicodedata

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LISTS = pathlib.Path(__file__).resolve().parent.parent.parent / "src" / "kit" / "wordlists"
LANGS = [("es", "spanish"), ("pt", "portuguese"), ("en", "english")]


def load():
    out = {}
    for code, name in LANGS:
        words = (LISTS / f"{name}.txt").read_bytes().decode("utf-8").split("\n")
        assert words[-1] == "" and len(words) == 2049
        out[code] = words[:2048]
    return out


def fold(w):
    return "".join(c for c in unicodedata.normalize("NFKD", w) if not unicodedata.combining(c)).lower()


def check(entropy):
    d = hashlib.sha256(b"trino/kit/v1/check" + entropy).digest()
    return (d[0] << 4) | (d[1] >> 4)


def indices(entropy):
    n = (int.from_bytes(entropy, "big") << 12) | check(entropy)
    return [(n >> (11 * (11 - i))) & 0x7FF for i in range(12)]


def entropy_of(idx):
    n = 0
    for i in idx:
        n = (n << 11) | i
    return (n >> 12).to_bytes(15, "big"), n & 0xFFF


def valid(idx):
    e, c = entropy_of(idx)
    return check(e) == c


def keys(entropy):
    k = Argon2id(salt=b"trino/kit/v1", length=32, iterations=3, lanes=1, memory_cost=64 * 1024).derive(entropy)

    def hk(info):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(k)

    return k, hk(b"trino/kit/v1/reserve"), hk(b"trino/kit/v1/check-local")


def ambiguous(lists):
    es = {fold(w): i for i, w in enumerate(lists["es"])}
    en = {fold(w): i for i, w in enumerate(lists["en"])}
    shared = sorted(set(es) & set(en))
    for combo in itertools.product(shared, repeat=12):
        if valid([es[w] for w in combo]) and valid([en[w] for w in combo]):
            return list(combo)
    raise SystemExit("no ambiguous kit found")


def ambiguous_prefixes(lists):
    """Four-letter prefixes, none of them a whole word, that name one word in
    Spanish and one in English, and pass the check in both."""
    es_words = [fold(w) for w in lists["es"]]
    en_words = [fold(w) for w in lists["en"]]

    def by_prefix(words):
        out = {}
        for i, w in enumerate(words):
            if len(w) > 4:
                out.setdefault(w[:4], []).append(i)
        return {p: v[0] for p, v in out.items() if len(v) == 1}

    es, en = by_prefix(es_words), by_prefix(en_words)
    whole = set(es_words) | set(en_words)
    shared = sorted(p for p in set(es) & set(en) if p not in whole)[:12]
    for combo in itertools.product(shared, repeat=12):
        if valid([es[p] for p in combo]) and valid([en[p] for p in combo]):
            return list(combo), es, en
    raise SystemExit("no ambiguous prefixes found")


def main():
    lists = load()
    entropies = [bytes(15), b"\xff" * 15] + [
        hashlib.sha256(f"trino/kit/vector/{i}".encode()).digest()[:15] for i in range(6)
    ]
    out = {"generator": "tests/vectors/kit.py", "words": [], "keys": []}
    for e in entropies:
        idx = indices(e)
        case = {"entropy": e.hex(), "check": check(e), "indices": idx}
        for code, _ in LANGS:
            words = [lists[code][i] for i in idx]
            case[code] = words
            # What a person types: composed (NFC) letters, as a keyboard gives them.
            case[f"{code}_nfc"] = " ".join(unicodedata.normalize("NFC", w) for w in words)
        out["words"].append(case)
    for e in entropies[:3]:
        k, k_reserva, h_check = keys(e)
        out["keys"].append({"entropy": e.hex(), "k": k.hex(), "k_reserva": k_reserva.hex(), "h_check": h_check.hex()})
    words = ambiguous(lists)
    es = {fold(w): i for i, w in enumerate(lists["es"])}
    en = {fold(w): i for i, w in enumerate(lists["en"])}
    out["ambiguous"] = {
        "words": words,
        "es_entropy": entropy_of([es[w] for w in words])[0].hex(),
        "en_entropy": entropy_of([en[w] for w in words])[0].hex(),
    }
    prefixes, es_p, en_p = ambiguous_prefixes(lists)
    out["ambiguous_prefixes"] = {
        "words": prefixes,
        "es_entropy": entropy_of([es_p[p] for p in prefixes])[0].hex(),
        "en_entropy": entropy_of([en_p[p] for p in prefixes])[0].hex(),
    }
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

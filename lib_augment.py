"""Obfuscation augmenter for IAAC command-intent training data.

Teaches the model invariance to the obfuscation tricks attackers use to disguise
known techniques. Applied to ATTACK classes only, at train time only (never to
the val/test splits, never to BENIGN/ADMIN). See ml_build.md §8.
"""
import base64

ATTACK_CLASSES = {"RECON", "EXPLOIT", "PERSISTENCE", "EXFILTRATION"}


def _b64(cmd, shell):
    enc = base64.b64encode(cmd.encode()).decode()
    return f"echo {enc}|base64 -d|{shell}"


def _ifs(cmd):
    # replace spaces with ${IFS} — classic space-evasion
    return cmd.replace(" ", "${IFS}")


def _linecont(cmd):
    p = cmd.split(" ", 1)
    return p[0] + " \\\n" + p[1] if len(p) == 2 else cmd


def _quotesplit(cmd):
    # split the first token with empty quotes: bash -> ba""sh
    p = cmd.split(" ", 1)
    t = p[0]
    if len(t) >= 4:
        m = len(t) // 2
        t = t[:m] + '""' + t[m:]
    return t + ((" " + p[1]) if len(p) == 2 else "")


def _varindirect(cmd):
    # variable indirection on the first token: c=<tok>;$c <rest>
    p = cmd.split(" ", 1)
    rest = (" " + p[1]) if len(p) == 2 else ""
    return f"c={p[0]};$c{rest}"


def _wsjitter(cmd, rng):
    toks = [t for t in cmd.split(" ") if t != ""]
    seps = ["  ", " \t", "   "]
    return rng.choice(seps).join(toks)


_ALL = [
    lambda c, r: _b64(c, "bash"),
    lambda c, r: _b64(c, "sh"),
    lambda c, r: _ifs(c),
    lambda c, r: _linecont(c),
    lambda c, r: _quotesplit(c),
    lambda c, r: _varindirect(c),
    lambda c, r: _wsjitter(c, r),
]


def augment_variants(cmd, rng, k):
    """Return up to k distinct obfuscated variants of cmd (label unchanged)."""
    funcs = _ALL[:]
    rng.shuffle(funcs)
    out, seen = [], {cmd}
    for f in funcs:
        try:
            v = f(cmd, rng)
        except Exception:
            continue
        if v and v not in seen:
            out.append(v)
            seen.add(v)
        if len(out) >= k:
            break
    return out

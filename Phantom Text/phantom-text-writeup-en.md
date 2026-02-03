# Phantom Text (HDNA Lab #150) — Zero‑Width Unicode Stego


## What’s going on
The blog post looks normal, but it contains *invisible* Unicode **format** characters (General Category **`Cf`**) embedded inside visible text.
In this challenge, the hidden payload is carried by two zero‑width characters:

- `U+200B` **ZWSP** — Zero Width Space  
- `U+200C` **ZWNJ** — Zero Width Non‑Joiner

Because these characters have **no visible width**, they can be used as a covert channel inside an “ordinary” paragraph.

---

## Why “copy/paste” often fails
Some editors, messaging apps, or web pipelines may **normalize** or **strip** certain zero‑width characters (especially `U+200B`), which breaks decoding.
So you want the **raw HTML** (or the raw copied text from the HTML source), not a sanitized rendering.

---

## Attack plan (repeatable / CTF‑friendly)

### 1) Download the page as raw HTML
```bash
curl -sL 'https://lab.hdna.me/150-phantom-text/' -o phantom.html
```

### 2) Identify suspicious invisible characters
A quick way is to scan for characters in Unicode category `Cf`:

```python
import unicodedata
from collections import Counter
from pathlib import Path

html = Path("phantom.html").read_text(encoding="utf-8")

cf = [ch for ch in html if unicodedata.category(ch) == "Cf"]
print("Total Cf chars:", len(cf))

counts = Counter(cf)
for ch, n in counts.most_common():
    print(f"U+{ord(ch):04X}", unicodedata.name(ch, "UNKNOWN"), n)
```

In this challenge, you’ll see mainly `U+200B` and `U+200C` clustered right after **“Welcome”** inside a `<strong>...</strong>` element.

---

## Decoding logic (the key step)

### 3) Extract the invisible stream from the “Welcome …” `<strong>`
Then decode using a 1‑bit mapping:

- `ZWSP (U+200B) = 0`
- `ZWNJ (U+200C) = 1`

Why this works here:
- The file contains **288 bits**, i.e. **36 bytes** once grouped into octets.
- An ASCII UUID with hyphens is **36 characters** long (`8-4-4-4-12`), so the output fits perfectly.

### 4) Full decoder script (copy/paste runnable)
```python
import re
import unicodedata
from pathlib import Path

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

html = Path("phantom.html").read_text(encoding="utf-8")

# Grab the first <strong>...</strong> (the one containing "Welcome")
start = html.index("<strong>") + len("<strong>")
end = html.index("</strong>", start)
strong = html[start:end]

# Pull the zero-width / format characters (Unicode General Category = Cf)
cf_stream = "".join(ch for ch in strong if unicodedata.category(ch) == "Cf")

ZWSP, ZWNJ = "\u200b", "\u200c"

# Map characters to bits
bits = "".join("0" if ch == ZWSP else "1" for ch in cf_stream)

# Convert bits -> bytes
bits = bits[:len(bits) - (len(bits) % 8)]
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# Decode as ASCII and extract UUID
txt = data.decode("ascii", errors="ignore")
m = UUID_RE.search(txt)
print("Flag:", m.group(0) if m else txt)
```

Expected output:
```
Flag: [REDACTED]
```

---

## Troubleshooting / variations
If you *don’t* get readable output:

1. **You lost characters** (normalization). Re-download the raw HTML and decode from that.
2. The challenge might use a different mapping (swap `0/1`) or more symbols (e.g. `U+200D`, `U+2060`, `U+FEFF`).  
   Try alternative mappings and decode as `utf-8` or `utf-16`.

---

## Notes
- This is a classic “zero‑width Unicode steganography” pattern: embed a stream of ZW characters in otherwise normal text and map them to bits.
- General Category `Cf` (“Other, Format”) is a good heuristic to locate this kind of payload.

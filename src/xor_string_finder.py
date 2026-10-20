"""XOR String Finder for IDA Pro 9.3 (IDAPython).

Searches segments for printable ASCII strings hidden by a single-byte XOR key.
UTF-16 and multi-byte keys are not handled.
Usage: File -> Script file...
"""

import heapq
import math
import re
from collections import Counter, namedtuple

import ida_bytes
import ida_kernwin
import ida_segment
import idautils


# ---------------------------------------------------------------------------
#   Configuration
# ---------------------------------------------------------------------------

TITLE = "XOR String Finder"
LOG_TAG = "[XOR Strings]"

MIN_LEN = 8                 # minimum decoded length (6 = more hits, more noise)
MAX_STRING_LEN = 64         # max decoded bytes kept per candidate
CHUNK_SIZE = 1 << 20        # scan segments in 1 MiB blocks
MAX_RESULTS = 3000          # keep only the best-scored candidates
SCAN_EXECUTABLE = True      # False = skip executable segments (less noise)
ADD_COMMENTS = False        # True = comment results (only where no comment exists)
PROGRESS_KEY_INTERVAL = 8   # update wait box / check Cancel every N keys

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
REPEATED_BYTE_RE = re.compile(rb"(.)\1{3,}")    # decoded zero padding, e.g. "AAAA"
IDENTITY = bytes(range(256))
# Key 0x20 only flips letter case, so it is skipped.
XOR_KEYS = tuple(key for key in range(1, 256) if key != 0x20)
XOR_TRANSLATIONS = {
    key: bytes.maketrans(IDENTITY, bytes(value ^ key for value in range(256)))
    for key in XOR_KEYS
}

COMMON_BIGRAMS = set((
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng "
    "se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si "
    "om ur"
).split())
COMMON_TOKENS = (
    "flag", "key", "password", "secret", "pass",
    "error", "warn", "info", "fail", "success",
)

COLUMNS = [
    ["XOR key", 8],
    ["Length", 7 | ida_kernwin.Choose.CHCOL_DEC],
    ["Score", 8],
    ["Decoded ASCII", 72],
]

XorResult = namedtuple("XorResult", "ea key text score")
_chooser = None  # keep a reference while the window is open


# ---------------------------------------------------------------------------
#   Helpers
# ---------------------------------------------------------------------------

class ScanCancelled(Exception):
    pass


def log(message):
    ida_kernwin.msg("%s %s\n" % (LOG_TAG, message))


def is_repetitive_noise(text):
    """Reject long low-complexity strings and short-period patterns."""
    length = len(text)
    if length < 24:
        return False

    counts = Counter(text)
    entropy = -sum(
        (c / float(length)) * math.log2(c / float(length)) for c in counts.values()
    )

    # Periodic motifs ("EDEDED...") that contain no run of identical chars.
    max_period_match = 0.0
    for period in range(2, min(9, length // 3 + 1)):
        matches = sum(text[i] == text[i - period] for i in range(period, length))
        max_period_match = max(max_period_match, matches / float(length - period))

    if max_period_match >= 0.62:
        return True
    return entropy < 2.45 and max(counts.values()) / float(length) >= 0.35


def score_candidate(raw_text):
    """Return a text-likelihood score, or None if the run looks implausible."""
    text = raw_text.decode("ascii", "strict")
    length = len(text)
    if length < MIN_LEN:
        return None

    counts = Counter(text)
    if len(counts) < 4 or max(counts.values()) / float(length) > 0.65:
        return None
    if is_repetitive_noise(text):
        return None

    alpha_count = sum(ch.isalpha() for ch in text)
    alnum_count = alpha_count + sum(ch.isdigit() for ch in text)
    alpha_ratio = alpha_count / float(length)
    if alpha_count < max(3, int(length * 0.18)):
        return None
    if alnum_count / float(length) < 0.30:
        return None

    lower = text.lower()
    letters = [ch for ch in lower if "a" <= ch <= "z"]
    vowel_ratio = sum(ch in "aeiou" for ch in letters) / float(len(letters)) if letters else 0.0

    # English text is ~38% vowels: reward closeness to it, penalise vowel soup.
    vowel_plausibility = max(0.0, 1.0 - abs(vowel_ratio - 0.38) / 0.38)
    vowel_penalty = max(0.0, vowel_ratio - 0.65) * 20.0

    pairs = [l + r for l, r in zip(lower, lower[1:]) if "a" <= l <= "z" and "a" <= r <= "z"]
    bigram_ratio = sum(p in COMMON_BIGRAMS for p in pairs) / float(len(pairs)) if pairs else 0.0

    length_bonus = min(4.0, 1.5 * math.log2(max(1.0, length / float(MIN_LEN))))
    token_bonus = 7.0 * sum(token in lower for token in COMMON_TOKENS)

    score = (length_bonus + alpha_ratio * 8.0 + vowel_plausibility * 3.0
             - vowel_penalty + bigram_ratio * 8.0 + token_bonus)
    if any(ch in text for ch in "_-/.:\\"):
        score += 1.0
    return score


def add_candidate(heap, ea, key, raw_text):
    """Score a candidate and keep it in the bounded top-N heap."""
    raw_text = raw_text[:MAX_STRING_LEN]
    score = score_candidate(raw_text)
    if score is None:
        return

    entry = (score, -ea, key, raw_text.decode("ascii"))   # ties: lower address wins
    if len(heap) < MAX_RESULTS:
        heapq.heappush(heap, entry)
    elif entry > heap[0]:
        heapq.heapreplace(heap, entry)


def split_padding(run):
    """Yield (offset, piece) of a printable run without repeated-byte islands."""
    cursor = 0
    for repeated in REPEATED_BYTE_RE.finditer(run):
        if repeated.start() > cursor:
            yield cursor, run[cursor:repeated.start()]
        cursor = repeated.end()
    if cursor < len(run):
        yield cursor, run[cursor:]


def collect_segments():
    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None or seg.end_ea <= seg.start_ea:
            continue
        if seg.type == ida_segment.SEG_BSS:
            continue
        if not SCAN_EXECUTABLE and (seg.perm & ida_segment.SEGPERM_EXEC):
            continue
        segments.append(seg)
    return segments


# ---------------------------------------------------------------------------
#   Scan
# ---------------------------------------------------------------------------

def scan_segments(segments):
    heap = []
    total_bytes = sum(seg.end_ea - seg.start_ea for seg in segments)
    scanned = 0
    cancelled = False

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box("NODELAY\nSearching for single-byte XOR strings...")
    try:
        for seg_index, seg in enumerate(segments, 1):
            seg_start = seg.start_ea
            seg_size = seg.end_ea - seg.start_ea

            for base in range(0, seg_size, CHUNK_SIZE):
                owned_size = min(CHUNK_SIZE, seg_size - base)
                # Overlap lets strings cross chunk borders; a chunk only reports
                # matches that start inside [owned_start, owned_end).
                read_start = max(0, base - MAX_STRING_LEN)
                read_end = min(seg_size, base + CHUNK_SIZE + MAX_STRING_LEN)
                raw = ida_bytes.get_bytes(seg_start + read_start, read_end - read_start)
                if raw is None:
                    log("Cannot read 0x%X, chunk skipped." % (seg_start + read_start))
                    scanned += owned_size
                    continue

                owned_start = base - read_start
                owned_end = owned_start + owned_size

                for key in XOR_KEYS:
                    if key % PROGRESS_KEY_INTERVAL == 0:
                        ida_kernwin.replace_wait_box(
                            "XOR scan: segment %d/%d, offset 0x%X, key 0x%02X\n"
                            "Candidates retained: %d" % (seg_index, len(segments), base, key, len(heap))
                        )
                        if ida_kernwin.user_cancelled():
                            raise ScanCancelled()

                    decoded = raw.translate(XOR_TRANSLATIONS[key])
                    for match in PRINTABLE_RE.finditer(decoded):
                        for offset, piece in split_padding(match.group()):
                            local = match.start() + offset
                            if owned_start <= local < owned_end:
                                add_candidate(heap, seg_start + read_start + local, key, piece)

                scanned += owned_size
    except ScanCancelled:
        cancelled = True
    finally:
        ida_kernwin.hide_wait_box()

    results = [XorResult(-neg_ea, key, text, score) for score, neg_ea, key, text in heap]
    results.sort(key=lambda item: (-item.score, item.ea))
    return results, cancelled, scanned, total_bytes


def annotate(results):
    """Add repeatable comments where the address has no comment yet."""
    count = 0
    for item in results:
        if (ida_bytes.get_cmt(item.ea, False) or "").strip():
            continue
        if (ida_bytes.get_cmt(item.ea, True) or "").strip():
            continue
        comment = 'XOR candidate: key=0x%02X, len=%d, decoded="%s"' % (
            item.key, len(item.text), item.text)
        if ida_bytes.set_cmt(item.ea, comment, True):
            count += 1
    return count


# ---------------------------------------------------------------------------
#   Chooser
# ---------------------------------------------------------------------------

class ResultChooser(ida_kernwin.Choose):
    """Rows are (ea, [cells...]); the Address column is added automatically."""

    def __init__(self, title, columns, rows):
        cols = [["Address", 14 | ida_kernwin.Choose.CHCOL_EA]] + columns
        super().__init__(title, cols, flags=ida_kernwin.Choose.CH_QFLT)
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        ea, cells = self.rows[n]
        return ["0x%X" % ea] + list(cells)

    def OnGetEA(self, n):
        return self.rows[n][0]


def show_results(results):
    global _chooser
    if not results:
        log("No candidates passed the filters. Try MIN_LEN=6 or other segment settings.")
        return
    rows = [
        (r.ea, ["0x%02X" % r.key, str(len(r.text)), "%6.1f" % r.score, r.text])
        for r in results
    ]
    _chooser = ResultChooser(TITLE, COLUMNS, rows)
    _chooser.Show()


# ---------------------------------------------------------------------------
#   Main
# ---------------------------------------------------------------------------

def main():
    segments = collect_segments()
    if not segments:
        log("No segments to scan.")
        return

    log("Scanning %d segment(s), min length %d, executable segments %s." % (
        len(segments), MIN_LEN, "included" if SCAN_EXECUTABLE else "skipped"))
    results, cancelled, scanned, total = scan_segments(segments)

    log("Scan %s: %d / %d bytes, %d candidate(s) (limit %d)." % (
        "cancelled" if cancelled else "finished", scanned, total, len(results), MAX_RESULTS))
    if ADD_COMMENTS:
        log("Comments added: %d" % annotate(results))
    show_results(results)


if __name__ == "__main__":
    main()

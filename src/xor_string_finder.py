"""XOR String Finder for IDA Pro 9.3

    | Searches IDA segments for ASCII strings 
    | encoded with a repeating 1-byte XOR key.

USAGE: File -> Script file...
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
# CONFIGURATION
# ---------------------------------------------------------------------------
MIN_LEN = 8                 # Minimum decoded ASCII string length; try 6 for more hits/noise.
MAX_STRING_LEN = 64         # Maximum decoded bytes retained for one candidate.
CHUNK_SIZE = 1 << 20        # Scan segments in 1 MiB blocks to limit memory usage.
MAX_RESULTS = 3000          # Keep the highest-ranked candidates in the chooser.
SCAN_EXECUTABLE = True      # False = skip executable segments (often reduces noise).
ADD_COMMENTS = False        # True = add repeatable comments, but only where no comment exists.
PROGRESS_KEY_INTERVAL = 8   # Update wait-box/cancellation check every N XOR keys.

# Printable ASCII only. UTF-16 and multi-byte/repeating XOR keys are not handled.
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
REPEATED_BYTE_RE = re.compile(rb"(.)\1{3,}")  # padding often decodes to repeated printable bytes
IDENTITY = bytes(range(256))
# 0x20 mainly toggles ASCII letter case (uppercase <-> lowercase), so it is
# excluded to avoid ranking case-transformed plain strings as XOR-encoded data.
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

XorResult = namedtuple("XorResult", "ea key text score")
_XOR_CHOOSER = None  # Keep the chooser object alive while its window is open.


class ScanCancelled(Exception):
    pass


def is_repetitive_noise(text):
    """Reject long low-complexity strings and short-period character patterns."""
    length = len(text)
    if length < 24:
        return False

    counts = Counter(text)
    entropy = -sum(
        (count / float(length)) * math.log2(count / float(length))
        for count in counts.values()
    )

    # Detect repeated motifs such as "EDEDEDE..." even when no single run
    # contains four identical characters. Compare each character with the
    # character a short distance earlier (periods 2..8).
    max_period_match = 0.0
    for period in range(2, min(9, length // 3 + 1)):
        pairs = length - period
        matches = sum(text[i] == text[i - period] for i in range(period, length))
        max_period_match = max(max_period_match, matches / float(pairs))

    # Periodic patterns are strong noise signals. The entropy fallback catches
    # highly skewed, low-complexity data that is not strictly periodic.
    if max_period_match >= 0.62:
        return True
    if entropy < 2.45 and max(counts.values()) / float(length) >= 0.35:
        return True
    return False


def score_candidate(raw_text):
    """Return a heuristic score, or None if the decoded run looks implausible."""
    text = raw_text.decode("ascii", "strict")
    length = len(text)
    if length < MIN_LEN:
        return None

    counts = Counter(text)
    if len(counts) < 4:
        return None
    # Filter obvious zero-padding / repeated-byte artefacts (e.g. "AAAAAAAA...").
    if max(counts.values()) / float(length) > 0.65:
        return None
    # Also reject patterned XOR artefacts such as "ExEAE^EGEDEDE...".
    if is_repetitive_noise(text):
        return None

    alpha_count = sum(ch.isalpha() for ch in text)
    digit_count = sum(ch.isdigit() for ch in text)
    alnum_count = alpha_count + digit_count
    alpha_ratio = alpha_count / float(length)
    if alpha_count < max(3, int(length * 0.18)):
        return None
    if alnum_count / float(length) < 0.30:
        return None

    lower = text.lower()
    letters = [ch for ch in lower if "a" <= ch <= "z"]
    vowel_ratio = (sum(ch in "aeiou" for ch in letters) / float(len(letters))) if letters else 0.0

    # English-like ASCII text often has roughly 30-45% vowels among letters.
    # Reward a plausible range instead of rewarding ever-higher ratios; strings
    # made almost entirely of vowels should not receive the maximum score.
    target_vowel_ratio = 0.38
    vowel_plausibility = max(
        0.0,
        1.0 - abs(vowel_ratio - target_vowel_ratio) / target_vowel_ratio,
    )
    vowel_penalty = max(0.0, vowel_ratio - 0.65) * 20.0

    bigram_hits = 0
    bigram_pairs = 0
    for left, right in zip(lower, lower[1:]):
        if "a" <= left <= "z" and "a" <= right <= "z":
            bigram_pairs += 1
            if left + right in COMMON_BIGRAMS:
                bigram_hits += 1

    # Use a ratio instead of an absolute count so long strings do not collect
    # an ever-growing bonus just because they contain more character pairs.
    bigram_ratio = bigram_hits / float(bigram_pairs) if bigram_pairs else 0.0

    # A bounded logarithmic length bonus gives longer strings a modest edge,
    # without letting length dominate the semantic/text-likelihood signals.
    length_bonus = min(
        4.0,
        1.5 * math.log2(max(1.0, length / float(MIN_LEN))),
    )

    token_bonus = 0.0
    for token in COMMON_TOKENS:
        if token in lower:
            token_bonus += 7.0

    # Rank coherent-looking text over arbitrary printable byte sequences.
    # Vowel plausibility is a modest bonus; extreme vowel-heavy text is penalized.
    score = (
        length_bonus
        + (alpha_ratio * 8.0)
        + (vowel_plausibility * 3.0)
        - vowel_penalty
        + (bigram_ratio * 8.0)
        + token_bonus
    )
    if any(ch in text for ch in "_-/.:\\"):
        score += 1.0
    return score


def add_candidate(heap, ea, key, raw_text):
    """Validate and add a candidate to a bounded top-N heap."""
    text_bytes = raw_text[:MAX_STRING_LEN]
    score = score_candidate(text_bytes)
    if score is None:
        return

    text = text_bytes.decode("ascii", "strict")
    # Higher score wins; for ties, prefer lower addresses for stable output.
    entry = (score, -ea, key, text)
    if len(heap) < MAX_RESULTS:
        heapq.heappush(heap, entry)
    elif entry > heap[0]:
        heapq.heapreplace(heap, entry)


def collect_segments():
    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        if seg.end_ea <= seg.start_ea:
            continue
        # BSS has no useful on-disk string bytes and may be very large.
        if getattr(seg, "type", None) == getattr(ida_segment, "SEG_BSS", object()):
            continue
        if not SCAN_EXECUTABLE and (seg.perm & ida_segment.SEGPERM_EXEC):
            continue
        segments.append(seg)
    return segments


def scan_segments(segments):
    heap = []
    total_bytes = sum(seg.end_ea - seg.start_ea for seg in segments)
    scanned_bytes = 0
    cancelled = False

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box("NODELAY\nSearching for single-byte XOR strings...")
    try:
        for seg_index, seg in enumerate(segments, 1):
            seg_start = seg.start_ea
            seg_size = seg.end_ea - seg.start_ea
            if seg_size <= 0:
                continue

            for base in range(0, seg_size, CHUNK_SIZE):
                # Overlap lets a string crossing a chunk boundary be found once.
                read_start = max(0, base - MAX_STRING_LEN)
                read_end = min(seg_size, base + CHUNK_SIZE + MAX_STRING_LEN)
                raw = ida_bytes.get_bytes(seg_start + read_start, read_end - read_start)
                if raw is None:
                    print("[XOR Finder] Could not read bytes at 0x%X; chunk skipped." % (seg_start + read_start))
                    scanned_bytes += min(CHUNK_SIZE, seg_size - base)
                    continue

                owned_start = base - read_start
                owned_end = owned_start + min(CHUNK_SIZE, seg_size - base)

                for key in XOR_KEYS:
                    if key % PROGRESS_KEY_INTERVAL == 0:
                        ida_kernwin.replace_wait_box(
                            "XOR scan: segment %d/%d, offset 0x%X, key 0x%02X\n"
                            "Best candidates retained: %d" %
                            (seg_index, len(segments), base, key, len(heap))
                        )
                        if ida_kernwin.user_cancelled():
                            raise ScanCancelled()

                    decoded = raw.translate(XOR_TRANSLATIONS[key])
                    for match in PRINTABLE_RE.finditer(decoded):
                        run = match.group()
                        # XOR can turn zero-padding into printable characters (e.g. 0x00 ^ 0x41 = 'A').
                        # Remove long repeated-byte islands so real text after/before padding is still discoverable.
                        cursor = 0
                        pieces = []
                        for repeated in REPEATED_BYTE_RE.finditer(run):
                            if repeated.start() > cursor:
                                pieces.append((cursor, run[cursor:repeated.start()]))
                            cursor = repeated.end()
                        if cursor < len(run):
                            pieces.append((cursor, run[cursor:]))
                        if not pieces:
                            pieces = [(0, run)]

                        for relative_start, piece in pieces:
                            local_start = match.start() + relative_start
                            # Each chunk owns only [base, base + CHUNK_SIZE); overlapping bytes are read-only context.
                            if local_start < owned_start or local_start >= owned_end:
                                continue
                            candidate = piece[:MAX_STRING_LEN]
                            ea = seg_start + read_start + local_start
                            add_candidate(heap, ea, key, candidate)

                scanned_bytes += min(CHUNK_SIZE, seg_size - base)

    except ScanCancelled:
        cancelled = True
    finally:
        ida_kernwin.hide_wait_box()

    results = [XorResult(-neg_ea, key, text, score) for score, neg_ea, key, text in heap]
    results.sort(key=lambda item: (-item.score, item.ea))
    return results, cancelled, scanned_bytes, total_bytes


def annotate_results(results):
    """Add repeatable comments only where both comment fields are empty."""
    if not ADD_COMMENTS:
        return 0

    annotated = 0
    for result in results:
        regular = ida_bytes.get_cmt(result.ea, False) or ""
        repeatable = ida_bytes.get_cmt(result.ea, True) or ""
        if regular.strip() or repeatable.strip():
            continue
        comment = "XOR candidate: key=0x%02X, len=%d, decoded=\"%s\"" % (
            result.key, len(result.text), result.text
        )
        if ida_bytes.set_cmt(result.ea, comment, True):
            annotated += 1
    return annotated


class XorResultsChooser(ida_kernwin.Choose):
    def __init__(self, results):
        self.results = results
        cols = [
            ["Address", 12 | ida_kernwin.Choose.CHCOL_EA],
            ["XOR key", 8],
            ["Length", 7],
            ["Score", 8],
            ["Decoded ASCII", 72],
        ]
        ida_kernwin.Choose.__init__(self, "XOR String Finder - candidates", cols, flags=ida_kernwin.Choose.CH_QFLT)

    def OnGetSize(self):
        return len(self.results)

    def OnGetLine(self, n):
        item = self.results[n]
        return [
            "0x%X" % item.ea,
            "0x%02X" % item.key,
            str(len(item.text)),
            "%.1f" % item.score,
            item.text,
        ]

    def OnGetEA(self, n):
        return self.results[n].ea


def main():
    global _XOR_CHOOSER

    segments = collect_segments()
    if not segments:
        print("[XOR Finder] No segments selected for scanning.")
        return

    print("[XOR Finder] IDA Pro 9.3 single-byte XOR scan started.")
    print("[XOR Finder] Segments: %d | min length: %d | executable segments: %s" % (
        len(segments), MIN_LEN, "included" if SCAN_EXECUTABLE else "skipped"
    ))

    results, cancelled, scanned_bytes, total_bytes = scan_segments(segments)
    annotated = annotate_results(results)

    print("[XOR Finder] Scan %s. Read %d / %d bytes." % (
        "cancelled" if cancelled else "finished", scanned_bytes, total_bytes
    ))
    print("[XOR Finder] Displaying %d best candidates (limit: %d)." % (len(results), MAX_RESULTS))
    if ADD_COMMENTS:
        print("[XOR Finder] Repeatable comments added: %d" % annotated)

    for item in results[:50]:
        print("[XOR] 0x%X  key=0x%02X  len=%d  score=%.1f  %s" % (
            item.ea, item.key, len(item.text), item.score, item.text
        ))
    if len(results) > 50:
        print("[XOR Finder] Remaining candidates are available in the chooser.")

    if results:
        _XOR_CHOOSER = XorResultsChooser(results)
        _XOR_CHOOSER.Show()
    else:
        print("[XOR Finder] No candidates passed the current filters. Try MIN_LEN=6 or review the segment settings.")


if __name__ == "__main__":
    main()

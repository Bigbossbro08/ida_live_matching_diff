"""
ida_matcher.matcher.engine.align
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Patience alignment over opcodes.
"""

import bisect
import difflib
from ida_matcher.matcher.engine.types import InstructionDiffRow

def _patience_common_matches(a, b, a_start, a_end, b_start, b_end):
    """(ai, bi) pairs for tokens that are unique in both segments."""
    b_pos, b_count = {}, {}
    for j in range(b_start, b_end):
        t = b[j]
        b_count[t] = b_count.get(t, 0) + 1
        b_pos[t] = j
    a_count = {}
    for i in range(a_start, a_end):
        t = a[i]
        a_count[t] = a_count.get(t, 0) + 1
    return [
        (i, b_pos[t])
        for i in range(a_start, a_end)
        if a_count[a[i]] == 1 and b_count.get(a[i], 0) == 1
        for t in (a[i],)
    ]

def _patience_lis(matches):
    """Longest increasing subsequence of (i, j) pairs (i and j strictly inc)."""
    if not matches:
        return []
    tails = []
    parent = {}
    tails_of_idx = {}
    for idx, (_i, j) in enumerate(matches):
        k = bisect.bisect_left(tails, j)
        if k == len(tails):
            tails.append(j)
        else:
            tails[k] = j
        parent[idx] = tails_of_idx.get(k - 1)
        tails_of_idx[k] = idx
    seq = []
    last = tails_of_idx[len(tails) - 1]
    while last is not None:
        seq.append(matches[last])
        last = parent[last]
    seq.reverse()
    return seq

def _lcs_opcodes(a, b, a_start, a_end, b_start, b_end):
    """Fallback LCS opcodes (global coords) for segments with no unique matches."""
    out = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
        None, a[a_start:a_end], b[b_start:b_end], autojunk=False
    ).get_opcodes():
        out.append((tag, a_start + i1, a_start + i2, b_start + j1, b_start + j2))
    return out

def _patience_rec(a, b, a_start, a_end, b_start, b_end, out):
    if a_start >= a_end or b_start >= b_end:
        if a_start < a_end:
            out.append(("delete", a_start, a_end, b_start, b_start))
        elif b_start < b_end:
            out.append(("insert", a_start, a_start, b_start, b_end))
        return
    pivots = _patience_lis(_patience_common_matches(a, b, a_start, a_end, b_start, b_end))
    if not pivots:
        out.extend(_lcs_opcodes(a, b, a_start, a_end, b_start, b_end))
        return
    _patience_rec(a, b, a_start, pivots[0][0], b_start, pivots[0][1], out)
    run_start_a, run_start_b = pivots[0]
    for k in range(1, len(pivots)):
        pi, pj = pivots[k]
        prev_i, prev_j = pivots[k - 1]
        if pi != prev_i + 1 or pj != prev_j + 1:
            out.append(("equal", run_start_a, prev_i + 1, run_start_b, prev_j + 1))
            _patience_rec(a, b, prev_i + 1, pi, prev_j + 1, pj, out)
            run_start_a, run_start_b = pi, pj
    out.append(("equal", run_start_a, pivots[-1][0] + 1, run_start_b, pivots[-1][1] + 1))
    _patience_rec(a, b, pivots[-1][0] + 1, a_end, pivots[-1][1] + 1, b_end, out)

def patience_diff(a, b):
    """Pure-Python Patience diff returning difflib-style opcode tuples.

    (tag, i1, i2, j1, j2) with tag in equal/replace/delete/insert.
    """
    out = []
    _patience_rec(a, b, 0, len(a), 0, len(b), out)
    return out

def insn_align(left_ops, right_ops):
    """Patience alignment over opcodes, with Replace-side padding (objdiff
    diff_instructions). Returns equal-length (left_rows, right_rows)."""
    opcodes = patience_diff([o.opcode for o in left_ops], [o.opcode for o in right_ops])
    left_rows, right_rows = [], []
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            for k in range(i2 - i1):
                left_rows.append(InstructionDiffRow(left_ops[i1 + k]))
                right_rows.append(InstructionDiffRow(right_ops[j1 + k]))
        elif tag == "replace":
            for k in range(max(i2 - i1, j2 - j1)):
                l = left_ops[i1 + k] if k < i2 - i1 else None
                r = right_ops[j1 + k] if k < j2 - j1 else None
                left_rows.append(InstructionDiffRow(l))
                right_rows.append(InstructionDiffRow(r))
        elif tag == "delete":
            for k in range(i2 - i1):
                left_rows.append(InstructionDiffRow(left_ops[i1 + k]))
                right_rows.append(InstructionDiffRow(None))
        elif tag == "insert":
            for k in range(j2 - j1):
                left_rows.append(InstructionDiffRow(None))
                right_rows.append(InstructionDiffRow(right_ops[j1 + k]))
    return left_rows, right_rows

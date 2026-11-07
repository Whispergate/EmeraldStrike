"""Static metadata extraction from CobaltStrike aggressor (.cna) scripts.

EmeraldStrike does NOT interpret Sleep. This module pattern-matches the few
lines that matter for BOF tasking (alias name, bof_pack format string,
beacon_inline_execute entrypoint, script_resource object path,
beacon_command_register help text) so register_bof can persist a schema
next to the .o file and inline_execute can auto-fill the argument format
string instead of making the operator hand-type it.

A .cna whose alias body contains control flow (argument inference, defaults,
conditional packing - e.g. RawHive's drive-letter positional logic) is marked
thin=False. The format string is still authoritative, but the operator UX the
.cna implements is NOT reproduced: the operator supplies arguments in
bof_pack order, one per format char.
"""

import re

FORMAT_CHARS = set("zZisb")

_TYPE_NAMES = {"z": "string", "Z": "wstring", "i": "int32", "s": "int16", "b": "binary"}

_CONTROL_FLOW_RE = re.compile(r"\b(if|else|for|while|foreach|switch|do)\b")

_ALIAS_RE = re.compile(r"\balias\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
_BOF_PACK_RE = re.compile(r"\bbof_pack\s*\([^,]+,\s*\"([^\"]*)\"")
_ENTRYPOINT_RE = re.compile(r"\bbeacon_inline_execute\s*\([^,]+,[^,]+,\s*\"([^\"]*)\"")
_OBJECT_RE = re.compile(r"\bscript_resource\s*\(\s*\"([^\"]+)\"")
_REGISTER_RE = re.compile(r"\bbeacon_command_register\s*\(")


def _decode_escapes(s: str) -> str:
    """Decode the common Sleep string escapes so help text renders with real newlines.

    Only \n and \t are decoded - any other backslash sequence (e.g. Windows
    paths in usage examples) is left untouched.
    """
    return s.replace("\\n", "\n").replace("\\t", "\t")


def _strip_strings(body: str) -> str:
    """Remove double-quoted string literals so keyword scans don't match help text."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', body)


def _balanced_body(text: str, open_idx: int) -> str:
    """Return the {...} body starting at text[open_idx] == '{', brace/quote aware."""
    depth = 0
    in_str = False
    esc = False
    for i in range(open_idx, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
    return text[open_idx + 1:]


def _call_string_literals(text: str, open_end: int) -> list:
    """Collect raw string literals inside the call whose '(' is at text[open_end - 1].

    Paren-depth aware so nested calls are traversed; escape aware. Raw literal
    text is kept (no escape decoding) - good enough for help display.
    """
    i = open_end
    depth = 1
    in_str = False
    esc = False
    lits = []
    start = None
    while i < len(text) and depth > 0:
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                lits.append(text[start:i])
                in_str = False
        else:
            if c == '"':
                in_str = True
                start = i + 1
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
        i += 1
    return lits


def _help_index(text: str) -> dict:
    """Map command name -> (short help, long help) from every beacon_command_register call.

    These calls live at top level, outside the alias body, so this scans the
    whole script; the first literal of each call is the command name.
    """
    idx = {}
    for m in _REGISTER_RE.finditer(text):
        lits = _call_string_literals(text, m.end())
        if len(lits) >= 2:
            idx[lits[0]] = (lits[1], "".join(lits[2:]))
    return idx


def parse_cna(text: str) -> list:
    """Extract one schema dict per `alias` block. Returns [] if nothing parses.

    Schema keys: alias, format (validated pack chars), format_raw (as written),
    entrypoint, object_path, help_short, help_long, thin (no control flow),
    parse_error (set when no bof_pack call was found in the alias body).
    """
    helps = _help_index(text)
    schemas = []
    for m in _ALIAS_RE.finditer(text):
        alias = m.group(1)
        body = _balanced_body(text, m.end() - 1)
        schema = {"schema_version": 1, "alias": alias}

        pm = _BOF_PACK_RE.search(body)
        if pm:
            raw = pm.group(1)
            schema["format"] = "".join(c for c in raw if c in FORMAT_CHARS)
            schema["format_raw"] = raw
        else:
            schema["parse_error"] = "no bof_pack call found in alias body"

        em = _ENTRYPOINT_RE.search(body)
        if em:
            schema["entrypoint"] = em.group(1)

        om = _OBJECT_RE.search(body)
        if om:
            schema["object_path"] = om.group(1)

        if alias in helps:
            short, long = helps[alias]
            schema["help_short"] = _decode_escapes(short)
            schema["help_long"] = _decode_escapes(long)

        # Keyword scan on string-stripped body. A false positive only downgrades
        # the UX claim (thin -> fat); it never affects the format string itself.
        schema["thin"] = _CONTROL_FLOW_RE.search(_strip_strings(body)) is None

        schemas.append(schema)
    return schemas


def schema_arg_hint(schema: dict) -> str:
    """Human-readable one-liner describing what arguments the BOF expects."""
    fmt = schema.get("format", "")
    names = ", ".join(_TYPE_NAMES.get(c, c) for c in fmt)
    hint = f"'{schema.get('alias', '?')}' expects {len(fmt)} argument(s) in bof_pack order: {names}"
    if schema.get("thin") is False:
        hint += " (fat .cna: positional inference/defaults from the aggressor script are NOT reproduced)"
    return hint

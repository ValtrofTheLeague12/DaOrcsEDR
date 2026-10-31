"""PyYAML facts the panel needs for more than one file.

Compose files and pipeline configs are both YAML shown to a human as coloured
source, and both need exactly the same two things from PyYAML: a value that is
JSON-safe, and character spans to paint. That lived inline in app.py, which was
fine while the compose viewer was the only consumer and is not fine now that the
analysis-configuration page reads `pipelines/*.yaml` the same way.

Every fact below comes out of PyYAML. Nothing here re-implements YAML:
safe_load for the data, compose() for the node tree.
"""

from __future__ import annotations

import yaml

# Scalar tag -> the token class the client colours. Anything absent from this
# map renders as a plain string, which is the right default for a YAML tag the
# panel does not model.
KIND = {
    "tag:yaml.org,2002:bool": "bool",
    "tag:yaml.org,2002:null": "null",
    "tag:yaml.org,2002:int": "number",
    "tag:yaml.org,2002:float": "number",
}


def jsonable(value):
    """Plain JSON out of whatever PyYAML inferred.

    A YAML file can hold !!timestamp and !!binary values, which are neither
    JSON primitives nor reliably encodable by the default encoder; str() is the
    honest rendering of a value this view only displays.
    """
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def spans(content: str) -> list[list]:
    """Character spans to colour in the raw text: [start, length, kind].

    compose() builds the node tree, which is the only thing that knows a scalar
    was a mapping KEY rather than a value - and the only thing carrying the
    start/end marks that make highlighting possible at all. safe_load() throws
    the marks away, so it can yield data but can never colour text.

    Comments come out of the gaps rather than out of PyYAML, because PyYAML has
    none to give: both compose() and scan() discard them outright in every
    version that ships (6.0.3 has no comment token at all). That is still not a
    hand-written YAML lexer - the node marks decide *where* everything is, and
    a gap can only hold whitespace, punctuation or a comment, because every
    quoted and plain scalar is itself a node with its own span. So the leftover
    text is classified, not parsed.

    Malformed YAML yields no spans and the client shows the text unhighlighted,
    which is the honest result: the file is broken and the read still works.
    """
    out: list[list] = []

    def mark(node, kind):
        start = node.start_mark.index
        out.append([start, node.end_mark.index - start, kind])

    def walk(node, as_key=False):
        if isinstance(node, yaml.MappingNode):
            if node.flow_style:
                out.append([node.start_mark.index, 1, "punct"])
            for key_node, value_node in node.value:
                walk(key_node, as_key=True)
                walk(value_node)
        elif isinstance(node, yaml.SequenceNode):
            if node.flow_style:
                out.append([node.start_mark.index, 1, "punct"])
            for item in node.value:
                walk(item)
        elif isinstance(node, yaml.ScalarNode):
            # A block scalar (| or >) is one node spanning every line of its
            # body, so the whole literal is coloured at once - including the
            # interior lines, which a line-at-a-time reader gets wrong.
            mark(node, "key" if as_key else KIND.get(node.tag, "string"))

    try:
        tree = yaml.compose(content)
    except yaml.YAMLError:
        return []
    if tree is None:
        return []
    walk(tree)
    out.sort(key=lambda s: s[0])

    # Fill the gaps between nodes. A `#` inside a gap can only be a comment:
    # inside a quoted scalar it is covered by that scalar's node, and in a plain
    # scalar YAML requires whitespace before `#`, which makes it a comment too.
    filled: list[list] = []
    cursor = 0

    def fill_gap(text, base):
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "#":
                end = text.find("\n", i)
                end = len(text) if end == -1 else end
                filled.append([base + i, end - i, "comment"])
                i = end
            elif ch in ".,[]{}":
                start = i
                while i < len(text) and text[i] in ".,[]{}":
                    i += 1
                filled.append([base + start, i - start, "punct"])
            else:
                i += 1

    for start, length, kind in out:
        if start > cursor:
            fill_gap(content[cursor:start], cursor)
        filled.append([start, length, kind])
        cursor = max(cursor, start + length)
    if cursor < len(content):
        fill_gap(content[cursor:], cursor)

    filled.sort(key=lambda s: s[0])
    # A file ending in a newline parses to a trailing empty scalar; a zero-length
    # span would render as an empty coloured run.
    return [s for s in filled if s[1] > 0]
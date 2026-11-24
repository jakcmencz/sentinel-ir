"""Patches tree-sitter-typescript v0.23.2 common/define-grammar.js for syntax the release rejects.

Usage: python3 patch-grammar.py path/to/common/define-grammar.js (edited in place).
Every edit must match exactly once, so a different upstream version fails
loudly instead of producing a half-patched grammar. See build.sh.
"""
import sys
p=sys.argv[1]; s=open(p).read()
def rep(a,b):
    global s
    assert s.count(a)==1, a[:70]
    s=s.replace(a,b)
# variance annotations (TS 4.7): interface A<in T>, <out T>, <in out T>, <const in T>.
# `out` becomes a keyword, so it is also listed where a name may stand
# (_type_identifier, _reserved_identifier): function f<out>(x: out), <out>x,
# <out>{a}</out> and `const out = 1` stay valid.
rep("""      type_parameter: $ => seq(
        optional('const'),
        field('name', $._type_identifier),""","""      type_parameter: $ => seq(
        optional('const'),
        optional('in'),
        optional('out'),
        field('name', $._type_identifier),""")
rep("""      _type_identifier: $ => alias($.identifier, $.type_identifier),""",
    """      _type_identifier: $ => choice(alias($.identifier, $.type_identifier), alias('out', $.type_identifier)),""")
rep("""        'object',
        'new',
        'readonly',
        previous,""","""        'object',
        'new',
        'readonly',
        'out',
        previous,""")
open(p,'w').write(s)

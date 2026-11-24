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
def rep_in(rule,a,b):
    # the first a after the rule head; a may be repeated elsewhere in the grammar
    global s
    assert s.count(rule)==1, rule
    i=s.index(rule); j=s.index(a,i)
    assert s.find('\n      },',i,j)==-1 and s.find(': $ =>',i+len(rule),j)==-1, rule
    s=s[:j]+b+s[j+len(a):]
# variance annotations (TS 4.7): interface A<in T>, <out T>, <in out T>, <const in T>.
# Only where TypeScript allows them (class, interface, type alias), so a <...>
# in an expression or a TSX tag parses as before. The modifier is any
# identifier before the name, not an `out` keyword: a keyword would stop `out`
# from being a name (const out, <out>x, out.Params, [out: T]). Accepting
# <foo T> too is fine for an analyzer.
rep("""      type_parameters: $ => seq(
        '<', commaSep1($.type_parameter), optional(','), '>',
      ),
""","""      type_parameters: $ => seq(
        '<', commaSep1($.type_parameter), optional(','), '>',
      ),

      _variance_type_parameters: $ => seq(
        '<', commaSep1(alias($._variance_type_parameter, $.type_parameter)), optional(','), '>',
      ),

      _variance_type_parameter: $ => seq(
        optional('const'),
        optional('in'),
        optional(alias($.identifier, $.variance_modifier)),
        field('name', $._type_identifier),
        field('constraint', optional($.constraint)),
        field('value', optional($.default_type)),
      ),
""")
for rule in ["      class: $ => prec('literal', seq(",
             "      abstract_class_declaration: $ => prec('declaration', seq(",
             "      class_declaration: $ => prec.left('declaration', seq(",
             "      interface_declaration: $ => seq(",
             "      type_alias_declaration: $ => seq("]:
    rep_in(rule, "field('type_parameters', optional($.type_parameters))",
           "field('type_parameters', optional(alias($._variance_type_parameters, $.type_parameters)))")
open(p,'w').write(s)

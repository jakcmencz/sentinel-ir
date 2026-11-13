"""Patches tree-sitter-rust v0.24.2 grammar.js for syntax the release rejects.

Usage: python3 patch-grammar.py path/to/grammar.js (edited in place).
Every edit must match exactly once, so a different upstream version fails
loudly instead of producing a half-patched grammar. See build.sh.
"""
import sys
p=sys.argv[1]; s=open(p).read()
def rep(a,b):
    global s
    assert s.count(a)==1, a[:70]
    s=s.replace(a,b)
# `pub type JsValue;` in extern blocks (wasm-bindgen / web-sys)
rep("""    associated_type: $ => seq(
      'type',""","""    associated_type: $ => seq(
      optional($.visibility_modifier),
      'type',""")
# `safe fn` / `safe static` in extern blocks
rep("""    function_modifiers: $ => repeat1(choice(
      'async',
      'default',
      'const',
      'unsafe',""","""    function_modifiers: $ => repeat1(choice(
      'async',
      'default',
      'const',
      'unsafe',
      'safe',""")
rep("""      optional($.visibility_modifier),
      'static',
""","""      optional($.visibility_modifier),
      optional(choice('safe', 'unsafe')),
      'static',
""")
# negative const generic arguments: Foo<-5, 5>
rep("""          $.lifetime,
          $._literal,
          $.block,
        ),
        optional($.trait_bounds),""","""          $.lifetime,
          $._literal,
          $.negative_literal,
          $.block,
        ),
        optional($.trait_bounds),""")
# where (): Trait, where mac!(T): Trait
rep("""        $.array_type,
        $.higher_ranked_trait_bound,
        alias(choice(...primitiveTypes), $.primitive_type),
      )),
      field('bounds', $.trait_bounds),""","""        $.array_type,
        $.unit_type,
        $.macro_invocation,
        $.higher_ranked_trait_bound,
        alias(choice(...primitiveTypes), $.primitive_type),
      )),
      field('bounds', $.trait_bounds),""")
# struct S where T: X;
rep("""        seq(
          field('body', $.ordered_field_declaration_list),
          optional($.where_clause),
          ';',
        ),
        ';',
      ),
    ),""","""        seq(
          field('body', $.ordered_field_declaration_list),
          optional($.where_clause),
          ';',
        ),
        seq(optional($.where_clause), ';'),
      ),
    ),""")
# attributes on tuple elements and struct pattern fields
rep("""      repeat($.attribute_item),
      seq($._expression, ','),
      repeat(seq($._expression, ',')),
      optional($._expression),
      ')',""","""      repeat($.attribute_item),
      seq($._expression, ','),
      repeat(seq(repeat($.attribute_item), $._expression, ',')),
      optional(seq(repeat($.attribute_item), $._expression)),
      ')',""")
rep("""    field_pattern: $ => seq(
      optional('ref'),""","""    field_pattern: $ => seq(
      repeat($.attribute_item),
      optional('ref'),""")
# `$` on its own inside macro token trees ([$] => ..., ($m:ident, $) => ...)
rep("""      'type', 'union', 'unsafe', 'use', 'where', 'while',
    ),""","""      'type', 'union', 'unsafe', 'use', 'where', 'while',
      prec(-1, '$'),
    ),""")
# nightly: const / auto traits, trait aliases, impl const, [const] / ~const bounds
rep("""    trait_item: $ => seq(
      optional($.visibility_modifier),
      optional('unsafe'),
      'trait',""","""    trait_item: $ => seq(
      optional($.visibility_modifier),
      optional('const'),
      optional('unsafe'),
      optional('auto'),
      'trait',""")
rep("""    impl_item: $ => seq(
      optional('unsafe'),
      'impl',
      field('type_parameters', optional($.type_parameters)),
      optional(seq(
        optional('!'),""","""    impl_item: $ => seq(
      optional('unsafe'),
      'impl',
      field('type_parameters', optional($.type_parameters)),
      optional(seq(
        optional('const'),
        optional('!'),""")
rep("""    trait_bounds: $ => seq(
      ':',
      sepBy1('+', choice(
        $._type,""","""    trait_bounds: $ => seq(
      ':',
      sepBy1('+', choice(
        $._type,
        $.const_trait_bound,
        $._bare_const_trait_bound,""")
rep("""    macro_definition: $ => {""","""    const_trait_bound: $ => seq(choice(seq('[', 'const', ']'), seq('~', 'const')), $._type),

    trait_alias_item: $ => seq(
      optional($.visibility_modifier),
      'trait',
      field('name', $._type_identifier),
      field('type_parameters', optional($.type_parameters)),
      '=',
      sepBy1('+', choice($._type, $.lifetime, $.higher_ranked_trait_bound, $.const_trait_bound)),
      optional($.where_clause),
      ';',
    ),

    // Declarative macros 2.0: `macro name(...) { ... }` / `macro name { rules }`
    macro_2_definition: $ => seq(
      optional($.visibility_modifier),
      'macro',
      field('name', $.identifier),
      optional(field('parameters', seq('(', repeat($._tokens), ')'))),
      field('body', seq('{', repeat($._tokens), '}')),
    ),

    macro_definition: $ => {""")
rep("""    _declaration_statement: $ => choice(
      $.const_item,""","""    _declaration_statement: $ => choice(
      $.const_item,
      $.trait_alias_item,
      $.macro_2_definition,""")
rep("""    [$._type, $._pattern],""","""    [$._type, $._pattern],
    [$.function_modifiers, $.trait_item],
    [$.function_modifiers, $.impl_item],
    [$.function_modifiers, $.impl_item, $.trait_item],
    [$.reference_type, $._pattern],
    [$._contextual_type_identifier, $._pattern],""")
# f16 / f128 (nightly float types and literal suffixes)
rep("""  'f32',
  'f64',
];""","""  'f16',
  'f32',
  'f64',
  'f128',
];""")
# `~` is now a token (for `~const`); keep it valid inside macro token trees
rep("""  '..', '...', '..=', ',', ';', ':', '::', '->', '=>', '#', '?',
];""","""  '..', '...', '..=', ',', ';', ':', '::', '->', '=>', '#', '?', '~',
];""")
# const impl<T> Foo<T> { ... }
rep("""    impl_item: $ => seq(
      optional('unsafe'),
      'impl',""","""    impl_item: $ => seq(
      optional('const'),
      optional('unsafe'),
      'impl',""")
# `impl [const] FnOnce`, bare `const Trait` bounds
rep("""const_trait_bound: $ => seq(choice(seq('[', 'const', ']'), seq('~', 'const')), $._type),""",
"""const_trait_bound: $ => prec(1, seq(choice(seq('[', 'const', ']'), seq('~', 'const')), $._type)),

    _bare_const_trait_bound: $ => alias(prec(1, seq('const', $._type)), $.const_trait_bound),""")
rep("""        $.bounded_type,
      ))),
    ),""","""        $.bounded_type,
        $.const_trait_bound,
      ))),
    ),""")
# const closures
rep("""      optional('static'),
      optional('async'),
      optional('move'),
      field('parameters', $.closure_parameters),""","""      optional('static'),
      optional('const'),
      optional('async'),
      optional('move'),
      field('parameters', $.closure_parameters),""")
# super let / let x = #[attr] expr
rep("""    let_declaration: $ => seq(
      'let',
      optional($.mutable_specifier),
      field('pattern', $._pattern),
      optional(seq(
        ':',
        field('type', $._type),
      )),
      optional(seq(
        '=',
        field('value', $._expression),""","""    let_declaration: $ => seq(
      optional('super'),
      'let',
      optional($.mutable_specifier),
      field('pattern', $._pattern),
      optional(seq(
        ':',
        field('type', $._type),
      )),
      optional(seq(
        '=',
        repeat($.attribute_item),
        field('value', $._expression),""")
# Tuple { 1: x, .. }
rep("""        seq(
          field('name', $._field_identifier),
          ':',
          field('pattern', $._pattern),
        ),
      ),
    ),

    remaining_field_pattern""","""        seq(
          field('name', choice($._field_identifier, $.integer_literal)),
          ':',
          field('pattern', $._pattern),
        ),
      ),
    ),

    remaining_field_pattern""")
rep("""    bounded_type: $ => prec.left(-1, seq(
      choice($.lifetime, $._type, $.use_bounds),
      '+',
      choice($.lifetime, $._type, $.use_bounds),
    )),""","""    bounded_type: $ => prec.left(-1, seq(
      choice($.lifetime, $._type, $.use_bounds, $.const_trait_bound),
      '+',
      choice($.lifetime, $._type, $.use_bounds, $.const_trait_bound),
    )),""")
# \u{4_e}: underscores are allowed in unicode escapes
assert s.count("/u\\{[0-9a-fA-F]+\\}/")==2
s=s.replace("/u\\{[0-9a-fA-F]+\\}/","/u\\{[0-9a-fA-F_]+\\}/")
# raw @ pattern (`raw` is only reserved after `&`)
rep("""    captured_pattern: $ => seq(
      $.identifier,""","""    captured_pattern: $ => seq(
      choice($.identifier, $._reserved_identifier),""")
# `safe` / `auto` are contextual keywords; keep them usable as names (`safe: bool`, `auto.x()`)
rep("""      'gen',
      'raw',
    ), $.identifier),""","""      'gen',
      'raw',
      'safe',
      'auto',
    ), $.identifier),""")
# str![...] (snapbox and others name a macro `str`)
rep("""      field('macro', choice(
        $.scoped_identifier,
        $.identifier,
        $._reserved_identifier,
      )),
      '!',""","""      field('macro', choice(
        $.scoped_identifier,
        $.identifier,
        $._reserved_identifier,
        alias('str', $.identifier),
      )),
      '!',""")
# turbofish in type position: `*const Gray::<T>`
rep("""        $.scoped_type_identifier,
      )),
      field('type_arguments', $.type_arguments),
    )),""","""        $.scoped_type_identifier,
      )),
      optional('::'),
      field('type_arguments', $.type_arguments),
    )),""")
# `&_` inside `fn(...)` types: `as fn(&_) -> _`
rep("""    reference_type: $ => seq(
      '&',
      optional($.lifetime),
      optional($.mutable_specifier),
      field('type', $._type),
    ),""","""    reference_type: $ => seq(
      '&',
      optional($.lifetime),
      optional($.mutable_specifier),
      field('type', choice($._type, alias('_', $.type_identifier))),
    ),""")
# `try!(...)` from edition 2015 code
rep("""        $._reserved_identifier,
        alias('str', $.identifier),
      )),""","""        $._reserved_identifier,
        alias('str', $.identifier),
        alias('try', $.identifier),
      )),""")
# ...and as type names (`x: safe`, `impl auto for T`, `dyn safe`)
s=s.replace("""    _type_identifier: $ => alias($.identifier, $.type_identifier),""","""    _type_identifier: $ => alias($.identifier, $.type_identifier),
    _contextual_type_identifier: $ => alias(choice('safe', 'auto'), $.type_identifier),""")
for rule in ('_type', 'impl_item', 'abstract_type', 'dynamic_type'):
    head = '    %s: $ => ' % rule
    assert s.count(head)==1, rule
    i = s.index(head); j = s.index("\n\n", i)
    body = s[i:j]
    assert body.count('$._type_identifier,')==1, rule
    s = s[:i] + body.replace('$._type_identifier,', '$._type_identifier,\n        $._contextual_type_identifier,') + s[j:]
open(p,'w').write(s)

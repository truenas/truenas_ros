# Fuzz dictionaries

Token hints, in the AFL/libFuzzer dictionary format
(<https://llvm.org/docs/LibFuzzer.html#dictionaries>). Pass one with
`-dict=`:

```sh
cargo +nightly fuzz run tree_cursor -- -dict=dicts/tree_cursor.dict
```

These carry the values a decoder gates on — a magic, a version word, a
grammar token — as plain text, so they can be read and reviewed like any
other source. They are hints, not fixtures: nothing here is required for a
target to work, and libFuzzer's comparison interception recovers most of
these on its own within seconds. Measured on this crate, a dictionary moved
coverage by 0 over a 30s run. They are kept because they cost nothing, they
document the wire formats in one place, and they help most exactly where
interception helps least — multi-byte grammar tokens rather than a single
`==` against a constant.

What does *not* belong here, or anywhere under version control: a corpus of
seed files. See the `Fuzzing` section of the top-level README.

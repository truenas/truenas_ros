#!/usr/bin/env python3
"""Differential oracle for the Rust ``configfile`` module.

Reads one INI document from stdin and emits a length-prefixed record stream
describing exactly how CPython's standard-library ``configparser`` parses,
serializes, and reads it. The Rust test (``test/configparser_compat.rs``) drives
this over a large corpus and asserts byte-for-byte and behavior parity, so this
script is the single source of truth for "same behavior as Python".

Stdlib only. To pin a specific ``configparser`` (e.g. the reviewed CPython
checkout), the Rust harness may set ``PYTHONPATH`` and/or pick the interpreter
via ``TRUENAS_ROS_PYTHON``; this script itself just ``import configparser``.

Wire format: a flat sequence of fields, each ``<decimal-len>\\n<len bytes>``,
so values containing newlines, tabs, or ``=`` are unambiguous.

Fields, in order:
  1. status: b"ok" or b"err"  -- RawConfigParser parse; on b"err" the stream
     ends here (the document is rejected).
  2. raw serialization, spaced  -- RawConfigParser.write(space_around=True)
  3. raw serialization, tight   -- RawConfigParser.write(space_around=False)
  4. nprobes: decimal count of (section, option) probes
  5. per probe, 10 fields:
       section, option,
       get_status,   get_value,      (ConfigParser.get, interpolated)
       int_status,   int_value,      (ConfigParser.getint)
       float_status, float_value,    (ConfigParser.getfloat)
       bool_status,  bool_value      (ConfigParser.getboolean)
     each *_status is b"ok"/b"err"; *_value is the utf-8 result or empty.
"""

import configparser
import io
import sys


def emit(out, field):
    out.write(str(len(field)).encode("ascii"))
    out.write(b"\n")
    out.write(field)


def serialize(parser, space_around):
    buf = io.StringIO()
    parser.write(buf, space_around_delimiters=space_around)
    return buf.getvalue().encode("utf-8")


def format_value(value):
    # bool is a subclass of int, so it must be checked first.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return repr(value)
    return str(value)


def emit_result(out, fn):
    try:
        value = fn()
    except Exception:
        emit(out, b"err")
        emit(out, b"")
        return
    emit(out, b"ok")
    emit(out, format_value(value).encode("utf-8"))


def main():
    out = sys.stdout.buffer
    doc = sys.stdin.buffer.read().decode("utf-8")

    raw = configparser.RawConfigParser()
    try:
        raw.read_string(doc)
    except Exception:
        emit(out, b"err")
        out.flush()
        return

    emit(out, b"ok")
    emit(out, serialize(raw, True))
    emit(out, serialize(raw, False))

    # A separate interpolating parser backs get()/getint/getfloat/getboolean.
    cp = configparser.ConfigParser()
    try:
        cp.read_string(doc)
    except Exception:
        emit(out, b"0")
        out.flush()
        return

    probes = []
    for section in cp.sections():
        for option in cp.options(section):
            probes.append((section, option))

    emit(out, str(len(probes)).encode("ascii"))
    for section, option in probes:
        emit(out, section.encode("utf-8"))
        emit(out, option.encode("utf-8"))
        emit_result(out, lambda s=section, o=option: cp.get(s, o))
        emit_result(out, lambda s=section, o=option: cp.getint(s, o))
        emit_result(out, lambda s=section, o=option: cp.getfloat(s, o))
        emit_result(out, lambda s=section, o=option: cp.getboolean(s, o))
    out.flush()


if __name__ == "__main__":
    main()

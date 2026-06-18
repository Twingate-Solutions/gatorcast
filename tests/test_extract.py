"""Tests for plaintext extraction + char->time offset index."""

from gatorcast.pipeline.extract import extract_plaintext, offset_at

HEADER = '{"version":2,"width":80,"height":24,"timestamp":1700000000}\n'


def test_joins_output_and_strips_ansi():
    cast = HEADER + '[0.5,"o","\\u001b[32mok\\u001b[0m ls\\r\\n"]\n[1.5,"o","rm -rf /tmp\\r\\n"]\n'
    r = extract_plaintext(cast)
    assert "ok ls" in r.text
    assert "rm -rf /tmp" in r.text
    assert "\x1b" not in r.text and "[32m" not in r.text  # ANSI gone


def test_char_offset_maps_to_event_time():
    cast = HEADER + '[0.5,"o","aaaa"]\n[9.0,"o","BOOM"]\n'
    r = extract_plaintext(cast)
    pos = r.text.index("BOOM")
    assert offset_at(r, pos) == 9.0
    assert offset_at(r, 0) == 0.5


def test_defensive_on_garbage():
    r = extract_plaintext("not a cast\n[bad line\n")
    assert isinstance(r.text, str)  # never raises


def test_empty_input():
    r = extract_plaintext("")
    assert r.text == ""
    assert offset_at(r, 0) is None


def test_ignores_non_output_events():
    # input "i" events and resize "r" events must not appear in the text
    cast = HEADER + '[0.1,"i","secret-keystroke"]\n[0.2,"o","visible"]\n'
    r = extract_plaintext(cast)
    assert "secret-keystroke" not in r.text
    assert "visible" in r.text

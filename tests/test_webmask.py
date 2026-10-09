"""Tests for ``gatorcast.pipeline.webmask`` (WEBAPP_SPEC section 5).

Pins the web-app URL storage form: normalized path kept verbatim (no path masking,
no ``proxy`` truncation), every query value masked with the quarter rule, keys kept
only when they look like plain identifiers, and a 4096-character cap applied after
masking.
"""

from __future__ import annotations

import re

import pytest

from gatorcast.pipeline import webmask
from gatorcast.pipeline.webmask import _MAX_URL, mask_query, mask_value, store_web_url

ALPHABET = "abcdefghijklmnopqrstuvwxyz"

# Everything mask_value may emit: safe revealed chars or "*", the ellipsis, then "(n)".
_MASKED_SHAPE = re.compile(r"[A-Za-z0-9._~*-]*…[A-Za-z0-9._~*-]*\(\d+\)")


# --------------------------------------------------------------------------- 5.7


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("/report?month=09", "/report?month=…(2)", id="short-value-nothing-revealed"),
        pytest.param(
            "/login?token=abc123def456", "/login?token=ab…6(12)", id="twelve-chars-2-plus-1"
        ),
        pytest.param(
            "/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl",
            "/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl",
            id="jwt-path-not-masked",
        ),
        pytest.param("/items/42", "/items/42", id="numeric-path-kept"),
        pytest.param(
            "/items/3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f",
            "/items/3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f",
            id="uuid-path-not-masked",
        ),
        pytest.param(
            "/proxy/settings?tab=general",
            "/proxy/settings?tab=g…(7)",
            id="no-proxy-truncation",
        ),
        pytest.param(
            "/search?q=quarterly+report&page=2",
            "/search?q=qu…rt(16)&page=…(1)",
            id="plus-decoded-before-masking",
        ),
        pytest.param(
            "/callback?Zm9vYmFyYmF6cXV4", "/callback?Zm…V4(16)", id="bare-item-masked-whole"
        ),
        pytest.param(
            "/app;jsessionid=0A1B2C3D4E5F6A7B8C9D/home",
            "/app;jsessionid=0A1B2C3D4E5F6A7B8C9D/home",
            id="matrix-parameter-not-masked",
        ),
        pytest.param(
            "/go?next=%2Fhome%3Fx%3D1", "/go?next=*h…(9)", id="unsafe-revealed-char-starred"
        ),
        pytest.param(
            "/api/v1/users?limit=50&continue=abc",
            "/api/v1/users?limit=…(2)&continue=…(3)",
            id="kubernetes-looking-keys-no-special-treatment",
        ),
        pytest.param(
            "/blog/release-notes-2024/", "/blog/release-notes-2024", id="trailing-slash-stripped"
        ),
        pytest.param("/a%252Fb?x=1", "/a%2Fb", id="double-encoded-path-drops-query"),
    ],
)
def test_store_web_url_matches_spec_worked_example(raw: str, expected: str) -> None:
    """Every WEBAPP_SPEC 5.7 row produces exactly the documented stored form."""
    assert store_web_url(raw) == expected


# ------------------------------------------------------------------- mask_value


def test_mask_value_empty_string_returns_empty_string() -> None:
    """An empty value has nothing to mask and no length suffix."""
    assert mask_value("") == ""


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (1, "…(1)"),
        (2, "…(2)"),
        (3, "…(3)"),
        (4, "a…(4)"),
        (5, "a…(5)"),
        (7, "a…(7)"),
        (8, "ab…(8)"),
        (9, "ab…(9)"),
        (11, "ab…(11)"),
        (12, "ab…l(12)"),
        (13, "ab…m(13)"),
        (15, "ab…o(15)"),
        (16, "ab…op(16)"),
        (17, "ab…pq(17)"),
        (26, "ab…yz(26)"),
    ],
)
def test_mask_value_quarter_rule_tier_boundaries(n: int, expected: str) -> None:
    """Revealed count is min(4, n // 4); boundaries at 4, 8, 12 and 16 (+/- 1)."""
    assert mask_value(ALPHABET[:n]) == expected


def test_mask_value_reveals_at_most_four_characters_for_long_values() -> None:
    """A very long value still reveals only 2 + 2 characters, plus its length."""
    value = "AB" + "x" * 996 + "YZ"
    assert mask_value(value) == "AB…YZ(1000)"


def test_mask_value_reveals_no_more_than_a_quarter_of_the_value() -> None:
    """For every length 1..40 the revealed characters never exceed n // 4 or 4."""
    for n in range(1, 41):
        masked = mask_value("a" * n)
        revealed = masked.split("…")[0] + masked.split("…")[1].split("(")[0]
        assert len(revealed) == min(4, n // 4), n
        assert masked.endswith(f"({n})")


def test_mask_value_appends_length_in_code_points() -> None:
    """The appended length counts code points, not bytes or UTF-16 units."""
    assert mask_value("😀" * 8) == "**…(8)"
    assert mask_value("é" * 4) == "*…(4)"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("/home?x=1", "*h…(9)", id="slash-prefix"),
        pytest.param("&=abcdefgh", "**…(10)", id="two-unsafe-prefix"),
        pytest.param("abcdefghijk ", "ab…*(12)", id="space-suffix-tier-3"),
        pytest.param("abcdefghijklmn/?", "ab…**(16)", id="two-unsafe-suffix"),
        pytest.param("%%abcdefgh", "**…(10)", id="percent-prefix"),
        pytest.param("\n\tabcdefgh", "**…(10)", id="control-chars-prefix"),
        pytest.param("#abcdefghijklmno", "*a…no(16)", id="hash-prefix-only-first"),
        pytest.param("abcdefghijklmn=#", "ab…**(16)", id="equals-and-hash-suffix"),
        pytest.param("éabcdefg", "*a…(8)", id="non-ascii-letter-starred"),
    ],
)
def test_mask_value_replaces_unsafe_revealed_characters_with_star(
    value: str, expected: str
) -> None:
    """Revealed characters outside [A-Za-z0-9._~-] become '*'."""
    assert mask_value(value) == expected


def test_mask_value_keeps_allowed_punctuation_when_revealed() -> None:
    """'.', '_', '~' and '-' are safe and are revealed unchanged."""
    assert mask_value("._~-abcdefgh") == "._…h(12)"
    assert mask_value("abcdefghijklmn~-") == "ab…~-(16)"
    assert mask_value("-_abcdefgh") == "-_…(10)"


def test_mask_value_unrevealed_unsafe_characters_never_leak() -> None:
    """Unsafe characters in the hidden middle are simply absent from the output."""
    masked = mask_value("ab" + "&=/?# %\n" * 3 + "yz")
    assert masked == "ab…yz(28)"
    assert _MASKED_SHAPE.fullmatch(masked)


def test_mask_value_output_never_contains_url_structural_characters() -> None:
    """Hostile input at every revealed position cannot introduce & = / ? # % or space."""
    hostile = "&=/?# %\n\t\r\\\"'<>"
    for value in (hostile, hostile * 3, "&" + "a" * 14 + "&", "=" * 40):
        masked = mask_value(value)
        assert _MASKED_SHAPE.fullmatch(masked), masked
        assert not set(masked) & set("&=/?# %\n\t\r\\\"'<>")


# ------------------------------------------------------------------- mask_query


def test_mask_query_masks_every_value_and_keeps_plain_keys() -> None:
    """Plain keys stay readable, values are always masked."""
    assert mask_query("a=hello&b=1") == "a=h…(5)&b=…(1)"


def test_mask_query_preserves_order_and_repeats() -> None:
    """Parts are emitted in input order; repeated keys are not merged."""
    assert mask_query("a=1&b=2&a=3") == "a=…(1)&b=…(1)&a=…(1)"


def test_mask_query_empty_value_stays_empty() -> None:
    """key= keeps the key and an empty value, with no length suffix."""
    assert mask_query("k=") == "k="
    assert mask_query("k=&j=1") == "k=&j=…(1)"


def test_mask_query_splits_value_at_first_equals_only() -> None:
    """Later '=' characters belong to the value, not to a further split."""
    assert mask_query("k=a=b=c") == "k=a…(5)"


def test_mask_query_splits_on_ampersand_only() -> None:
    """';' is not a separator, so 'a=1;b=2' is one value."""
    assert mask_query("a=1;b=2") == "a=1…(5)"


def test_mask_query_drops_empty_parts() -> None:
    """Empty parts between, before, and after separators disappear."""
    assert mask_query("&&a=1&&b=2&") == "a=…(1)&b=…(1)"


def test_mask_query_all_empty_parts_returns_empty_string() -> None:
    """A query with no non-empty part masks to the empty string."""
    assert mask_query("") == ""
    assert mask_query("&&") == ""


def test_mask_query_decodes_percent_and_plus_once() -> None:
    """%XX and '+' are decoded once before masking."""
    assert mask_query("k=%2B") == "k=…(1)"
    assert mask_query("k=a%2Bb+c") == "k=a…(5)"
    assert mask_query("k=+abcdefg") == "k=*a…(8)"


def test_mask_query_applies_unquote_plus_exactly_once_to_values() -> None:
    """A double-encoded value keeps its '%' after one decode (length differs)."""
    # Once: "%2F%2F%2F%2F" (12 chars). Twice would be "////" (4 chars).
    assert mask_query("k=%252F%252F%252F%252F") == "k=*2…F(12)"
    # Once: "%41" (3 chars). Twice would be "A" (1 char).
    assert mask_query("k=%2541") == "k=…(3)"


def test_mask_query_applies_unquote_plus_exactly_once_to_keys() -> None:
    """A double-encoded key decodes to 'a%41', which fails the key pattern."""
    assert mask_query("a%2541=v") == "a…(4)=…(1)"


def test_mask_query_emits_plain_keys_decoded() -> None:
    """An encoded key that decodes to a plain identifier is emitted decoded."""
    assert mask_query("a%5B0%5D=v") == "a[0]=…(1)"
    assert mask_query("a%2Eb=v") == "a.b=…(1)"


@pytest.mark.parametrize(
    "key",
    [
        pytest.param("a_b.c[0]-d", id="all-allowed-punctuation"),
        pytest.param("_", id="underscore"),
        pytest.param(".", id="dot"),
        pytest.param("[]", id="brackets"),
        pytest.param("-", id="hyphen"),
        pytest.param("Z9", id="mixed-case-digits"),
        pytest.param("k" * 64, id="sixty-four-chars"),
    ],
)
def test_mask_query_keeps_keys_matching_the_pattern(key: str) -> None:
    """Keys of 1-64 chars from [A-Za-z0-9_.\\[\\]-] stay in plaintext."""
    assert mask_query(f"{key}=abc") == f"{key}=…(3)"


def test_mask_query_masks_key_of_sixty_five_characters() -> None:
    """One character past the 64 limit and the key is masked as a value."""
    key = "k" * 65
    assert mask_query(f"{key}=abc") == "kk…kk(65)=…(3)"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("a%20b=xyz", "…(3)=…(3)", id="encoded-space"),
        pytest.param("a+b=xyz", "…(3)=…(3)", id="plus-becomes-space"),
        pytest.param("user:id=xyz", "u…(7)=…(3)", id="colon"),
        pytest.param("a%26b=xyz", "…(3)=…(3)", id="decoded-ampersand"),
        pytest.param("a%3Db=xyz", "…(3)=…(3)", id="decoded-equals"),
        pytest.param("a%0A=xyz", "…(2)=…(3)", id="trailing-newline"),
        pytest.param("a/b=xyz", "…(3)=…(3)", id="slash"),
        pytest.param("%C3%A9tat=xyz", "*…(4)=…(3)", id="non-ascii"),
    ],
)
def test_mask_query_masks_keys_outside_the_pattern(raw: str, expected: str) -> None:
    """A key that fails the pattern is masked with mask_value, like a value."""
    assert mask_query(raw) == expected


def test_mask_query_empty_key_is_masked_to_empty_text() -> None:
    """'=foo' has an empty key; mask_value('') is '', so the key is blank."""
    assert mask_query("=foo") == "=…(3)"


def test_mask_query_bare_items_are_masked_whole_without_equals() -> None:
    """A part with no '=' is decoded once, masked whole, and emitted bare."""
    assert mask_query("abcd") == "a…(4)"
    assert mask_query("Zm9vYmFyYmF6cXV4") == "Zm…V4(16)"
    assert mask_query("a%26b") == "…(3)"
    assert mask_query("a+b") == "…(3)"
    assert mask_query("%20") == "…(1)"


def test_mask_query_bare_item_is_decoded_exactly_once() -> None:
    """A double-encoded bare item keeps its '%' (12 chars, not 4)."""
    assert mask_query("%252F%252F%252F%252F") == "*2…F(12)"


def test_mask_query_mixes_bare_items_and_pairs_in_order() -> None:
    """Bare items and key=value parts interleave in input order."""
    assert mask_query("abcd&k=v&efgh") == "a…(4)&k=…(1)&e…(4)"


def test_mask_query_never_emits_the_plaintext_of_a_value() -> None:
    """No secret substring survives masking when the value is long enough."""
    masked = mask_query("token=s3cr3t-value-0123456789&sig=AAAABBBBCCCCDDDD")
    assert masked == "token=s3…89(23)&sig=AA…DD(16)"
    assert "cr3t-value" not in masked


# --------------------------------------------------------------- store_web_url


def test_store_web_url_without_query_returns_normalized_path() -> None:
    """No query: stored form is the normalized path with no '?'."""
    assert store_web_url("/a/b") == "/a/b"
    assert store_web_url("/") == "/"
    assert store_web_url("//a//b/") == "/a/b"


def test_store_web_url_empty_query_has_no_question_mark() -> None:
    """'/x?' normalizes to a path with no query and is stored without '?'."""
    assert store_web_url("/x?") == "/x"


def test_store_web_url_all_empty_masked_query_drops_the_question_mark() -> None:
    """A query whose parts are all empty masks to nothing and the '?' is dropped."""
    assert store_web_url("/x?&&") == "/x"
    assert store_web_url("/x?&") == "/x"


def test_store_web_url_empty_key_is_masked_not_dropped() -> None:
    """'?=foo' keeps its part, with a blank masked key."""
    assert store_web_url("/x?=foo") == "/x?=…(3)"


def test_store_web_url_plaintext_key_with_encoded_space_is_masked() -> None:
    """'a%20b' decodes to 'a b', fails the key pattern, and is masked."""
    assert store_web_url("/x?a%20b=foo") == "/x?…(3)=…(3)"


def test_store_web_url_drops_fragment() -> None:
    """The fragment never reaches storage, with or without a query."""
    assert store_web_url("/x#frag") == "/x"
    assert store_web_url("/x?a=bcd#frag") == "/x?a=…(3)"


def test_store_web_url_question_mark_in_value_stays_inside_the_value() -> None:
    """Only the first '?' splits path from query; later ones are value text."""
    assert store_web_url("/x?a=b?c") == "/x?a=…(3)"


def test_store_web_url_encoded_question_mark_in_path_cuts_path_and_drops_query() -> None:
    """normalize_url fail-closed rules apply unchanged to the web form."""
    assert store_web_url("/a%3Fb=secret?x=1") == "/a"
    assert store_web_url("/a%23b?x=1") == "/a"


# ------------------------------------------------------- paths are not masked


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(
            "/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl", id="jwt-shaped"
        ),
        pytest.param("/items/3f2b8c1e-9d4a-4c7b-8e2f-6a1b0c9d8e7f", id="uuid"),
        pytest.param("/dl/" + "deadbeef" * 8, id="long-hex"),
        pytest.param("/invite/Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56", id="mixed-case-token"),
        pytest.param("/app;jsessionid=0A1B2C3D4E5F6A7B8C9D/home", id="matrix-parameter"),
        pytest.param("/a/b;x=1;y=2/c", id="multiple-matrix-parameters"),
    ],
)
def test_store_web_url_does_not_mask_path_segments(path: str) -> None:
    """Path-embedded tokens are stored verbatim (WEBAPP_SPEC 5.3 withdrawn)."""
    assert store_web_url(path) == path


def test_store_web_url_keeps_path_segments_verbatim_next_to_a_masked_query() -> None:
    """Only the query is masked; the path in front of it is untouched."""
    assert (
        store_web_url("/reset/Ab12Cd34Ef56Gh78Ij90?token=abc123def456")
        == "/reset/Ab12Cd34Ef56Gh78Ij90?token=ab…6(12)"
    )


def test_store_web_url_unquotes_path_once_and_keeps_percent_bearing_result() -> None:
    """'%252F' unquotes once to '%2F' and the stored path keeps that literal text."""
    assert store_web_url("/a%252Fb") == "/a%2Fb"
    assert store_web_url("/files/100%2525") == "/files/100%25"


def test_store_web_url_double_encoded_path_drops_query() -> None:
    """A '%' left after the single unquote makes the query untrusted."""
    assert store_web_url("/a%2541?k=secretvalue") == "/a%41"


def test_store_web_url_path_segment_named_proxy_is_not_truncated() -> None:
    """'proxy' has no special meaning for web URLs: path and query are kept/masked."""
    assert store_web_url("/proxy/x/y?k=abcdefgh") == "/proxy/x/y?k=ab…(8)"
    assert store_web_url("/api/v1/proxy/deep/path") == "/api/v1/proxy/deep/path"


def test_store_web_url_does_not_apply_kubernetes_query_allowlist() -> None:
    """Keys such as container/limit get the same treatment as any other key."""
    assert store_web_url("/pods/p/exec?command=ls&container=app") == (
        "/pods/p/exec?command=…(2)&container=…(3)"
    )


# ------------------------------------------------------------------- 4096 cap


def test_max_url_constant_is_4096() -> None:
    """The documented cap is 4096 characters."""
    assert _MAX_URL == 4096
    assert webmask._MAX_URL == 4096


def test_store_web_url_at_the_cap_is_unchanged() -> None:
    """A stored URL of exactly 4096 characters is not truncated."""
    path = "/" + "a" * (_MAX_URL - 1)
    assert len(path) == _MAX_URL
    assert store_web_url(path) == path


def test_store_web_url_over_the_cap_is_truncated_to_4096() -> None:
    """One character over the cap is cut."""
    path = "/" + "a" * _MAX_URL
    stored = store_web_url(path)
    assert len(stored) == _MAX_URL
    assert stored == path[:_MAX_URL]


def test_store_web_url_cap_is_applied_after_masking_so_nothing_unmasked_leaks() -> None:
    """Truncation cuts the already-masked string: the query value is never plaintext."""
    path = "/" + "p" * 4090
    stored = store_web_url(f"{path}?k=secretsecretsecret")
    assert len(stored) == _MAX_URL
    assert stored == f"{path}?k=se"
    assert "secretsecret" not in stored


def test_store_web_url_many_masked_parameters_stay_within_the_cap() -> None:
    """A very long query is masked first and then bounded by the cap."""
    stored = store_web_url("/x?" + "&".join(f"k{i}=value{i}" for i in range(5000)))
    assert len(stored) == _MAX_URL
    assert stored.startswith("/x?k0=v…(6)&k1=v…(6)")
    assert "value" not in stored


# --------------------------------------------------------------------------- G: padded base64 tokens


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("dGVzdA==", "dG…(8)", id="double-pad-bare-token"),
        pytest.param("dGVzdA%3D%3D", "dG…(8)", id="double-pad-percent-encoded"),
        pytest.param("Zm9vYg==&a=1", "Zm…(8)&a=…(1)", id="double-pad-then-pair"),
        pytest.param("x=1&dGVzdA==", "x=…(1)&dG…(8)", id="pair-then-double-pad"),
        pytest.param("dGVz===", "d…(7)", id="triple-pad-all-equals-value"),
    ],
)
def test_mask_query_masks_a_double_padded_token_as_a_whole_bare_item(raw: str, expected: str) -> None:
    """G: ``?dGVzdA==`` splits as key ``dGVzdA`` / value ``=``; a value made only of ``=`` masks the whole item."""
    masked = mask_query(raw)
    assert masked == expected
    assert "dGVzdA" not in masked
    assert "VzdA" not in masked


def test_mask_query_double_padded_token_through_store_web_url() -> None:
    """The padded token never reaches the stored URL in the clear."""
    assert store_web_url("/x?dGVzdA==") == "/x?dG…(8)"


def test_mask_query_empty_value_keeps_its_key_and_equals() -> None:
    """G: ``flag=`` (empty value) is not a padded token: the plain key and the ``=`` stay."""
    assert mask_query("flag=") == "flag="
    assert mask_query("flag=&b=1") == "flag=&b=…(1)"
    assert store_web_url("/x?flag=") == "/x?flag="


def test_mask_query_single_padded_token_is_a_documented_limitation() -> None:
    """Pins a KNOWN GAP (documented limitation, WEBAPP_SPEC section 10).

    A single-pad token (``?dGVzdDE=``) splits as key ``dGVzdDE`` and an EMPTY value, which is
    indistinguishable from ``flag=``. The key matches the plain-key pattern, so the token is
    stored readable. If this ever changes, update this test and the spec's limitation note.
    """
    assert mask_query("dGVzdDE=") == "dGVzdDE="
    assert store_web_url("/x?dGVzdDE=") == "/x?dGVzdDE="


# --------------------------------------------------------------------------- B: provisional URL form


@pytest.mark.parametrize(
    ("kubernetes_url", "expected"),
    [
        pytest.param("/api/v1/pods", "/api/v1/pods", id="no-query"),
        pytest.param("/api/v1/pods?limit=500", "/api/v1/pods?limit=…(3)", id="allowlisted-key-masked-value"),
        pytest.param(
            "/api/v1/namespaces/x/pods/y/exec?container=app&stdin=true",
            "/api/v1/namespaces/x/pods/y/exec?container=…(3)&stdin=t…(4)",
            id="exec-flags-masked",
        ),
        pytest.param("/api/v1/services/s/proxy", "/api/v1/services/s/proxy", id="proxy-path-already-cut"),
        pytest.param("/x?", "/x", id="empty-query"),
    ],
)
def test_store_provisional_url_masks_values_on_top_of_the_kubernetes_form(
    kubernetes_url: str, expected: str
) -> None:
    """B: the provisional form is the Kubernetes URL with the web value masking applied to what is left."""
    assert webmask.store_provisional_url(kubernetes_url) == expected


def test_store_provisional_url_caps_at_4096_after_masking() -> None:
    """The cap is applied after masking, as for the web form."""
    stored = webmask.store_provisional_url("/" + "a" * 5000)
    assert len(stored) == _MAX_URL

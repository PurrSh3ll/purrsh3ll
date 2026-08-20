"""Tests for log secret redaction (core/app_logger.redact_secrets + filter).

Secrets must never reach a log file. redact_secrets scrubs key=value pairs,
Bearer tokens, provider-style sk- keys and secrets embedded in URL query params;
_SecretRedactingFilter applies it to a live log record. The core property under
test: the real secret value is gone from the output and REDACTED is present.
"""

import logging

from core.app_logger import redact_secrets, _SecretRedactingFilter


# --------------------------------------------------------------------------- #
# redact_secrets — patterns
# --------------------------------------------------------------------------- #
def test_key_equals_value_redacted():
    out = redact_secrets("api_key=abcd1234SECRET")
    assert "abcd1234SECRET" not in out
    assert "REDACTED" in out
    assert out.startswith("api_key=")


def test_colon_separated_secret_redacted():
    out = redact_secrets("password: hunter2pass")
    assert "hunter2pass" not in out
    assert "REDACTED" in out


def test_various_key_names_redacted():
    for kv in ("access_token=tok_abc123", "auth_token=zzz999", "secret=shh12345",
               "token=qwerty123", "API-KEY=Bignumber987"):
        out = redact_secrets(kv)
        assert "REDACTED" in out
        assert out.split("=", 1)[1].startswith("REDACTED") or "REDACTED" in out


def test_bearer_token_redacted():
    out = redact_secrets("Authorization: Bearer aGVsbG8xMjM0NTY3ODkw")
    assert "aGVsbG8xMjM0NTY3ODkw" not in out
    assert "Bearer ***REDACTED***" in out


def test_provider_sk_key_redacted():
    out = redact_secrets("using key sk-proj-abc123XYZ456def789ghi")
    assert "sk-proj-abc123XYZ456def789ghi" not in out
    assert "REDACTED" in out


def test_short_sk_like_token_is_not_touched():
    # "sk-" needs 12+ trailing chars to look like a real key.
    assert redact_secrets("sk-abc") == "sk-abc"


def test_url_query_key_redacted():
    out = redact_secrets("GET https://api.x/v1?api_key=SECRETVAL&q=1")
    assert "SECRETVAL" not in out
    assert "REDACTED" in out
    assert "q=1" in out          # non-secret param preserved


def test_multiple_secrets_all_redacted():
    out = redact_secrets("api_key=AAA111 and token=BBB222 and sk-cccccccccccc123")
    assert "AAA111" not in out and "BBB222" not in out
    assert "cccccccccccc123" not in out


def test_value_stops_at_delimiter():
    out = redact_secrets("token=SECRET, next=ok")
    assert "SECRET" not in out
    assert "next=ok" in out       # comma bounded the secret


# --------------------------------------------------------------------------- #
# no-op cases
# --------------------------------------------------------------------------- #
def test_empty_and_none_returned_unchanged():
    assert redact_secrets("") == ""
    assert redact_secrets(None) is None


def test_plain_text_unchanged():
    text = "scanning 10.10.10.5 on port 22 — nothing secret here"
    assert redact_secrets(text) == text


# --------------------------------------------------------------------------- #
# _SecretRedactingFilter — live log record
# --------------------------------------------------------------------------- #
def _record(msg, *args):
    return logging.LogRecord("t", logging.INFO, __file__, 1, msg, args, None)


def test_filter_rewrites_record_message():
    f = _SecretRedactingFilter()
    rec = _record("connecting with api_key=TOPSECRET123")
    assert f.filter(rec) is True
    assert "TOPSECRET123" not in rec.getMessage()
    assert "REDACTED" in rec.getMessage()


def test_filter_passes_clean_record_through():
    f = _SecretRedactingFilter()
    rec = _record("plain message %s", "value")
    assert f.filter(rec) is True
    assert rec.getMessage() == "plain message value"


def test_filter_clears_args_after_rewrite():
    # After redacting a %-formatted message the filter must drop args so the
    # stored (already-rendered) msg isn't re-formatted and crash.
    f = _SecretRedactingFilter()
    rec = _record("token=%s here", "SECRETX123")
    f.filter(rec)
    assert rec.getMessage()   # must not raise
    assert "SECRETX123" not in rec.getMessage()

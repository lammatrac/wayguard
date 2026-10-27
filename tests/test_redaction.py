import pytest

from wayguard.redaction import redact

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndef==\n-----END RSA PRIVATE KEY-----"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.mark.parametrize(
    ("raw", "secret", "kind"),
    [
        ("before\n" + PEM + "\nafter", "MIIEabc", "private_key"),
        ("-----BEGIN PRIVATE KEY-----\nMIIEtrunc", "MIIEtrunc", "private_key"),
        ("Authorization: Bearer abc123token", "abc123token", "authorization"),
        ("authorization: Basic dXNlcjpwdw==", "dXNlcjpwdw", "authorization"),
        ("curl -H 'x' Bearer zzzTOKEN999", "zzzTOKEN999", "bearer"),
        ("password=hunter2", "hunter2", "secret"),
        ("DB_PASSWD = 'p w'", "p w", "secret"),
        ("api_key=abcdef", "abcdef", "secret"),
        ("secret=s3 token=t4", "s3", "secret"),
        ("id AKIAIOSFODNN7EXAMPLE x", "AKIAIOSFODNN7EXAMPLE", "aws_key"),
        ("t ghp_" + "a" * 36, "a" * 36, "token"),
        ("t glpat-" + "b" * 20, "b" * 20, "token"),
        ("t sk-" + "c" * 30, "c" * 30, "token"),
        ("t xoxb-1234567890-abcdef", "1234567890", "token"),
        ("jwt " + JWT, "SflKxwRJSMeKKF2", "jwt"),
        ("Cookie: sid=abc; other=1", "sid=abc", "cookie"),
        ("Set-Cookie: sid=zzz; HttpOnly", "sid=zzz", "cookie"),
    ],
)
def test_redacts(raw: str, secret: str, kind: str) -> None:
    out = redact(raw)
    assert secret not in out
    assert f"[REDACTED:{kind}]" in out


def test_plain_text_untouched() -> None:
    s = "line one\nGET /index 200\nuser logged in\n"
    assert redact(s) == s


def test_large_pathological_input_is_fast() -> None:
    import time

    t = time.monotonic()
    redact("a" * 300_000 + "\n" + "password" * 30_000)
    assert time.monotonic() - t < 3

"""Unambiguous byte encoding for Fiat-Shamir transcripts and proof contexts."""


def encode_parts(*parts: bytes) -> bytes:
    """
    Concatenate parts, each prefixed with its length as 4 big-endian bytes.

    Plain concatenation is ambiguous (b"ab" + b"c" == b"a" + b"bc"), which can
    let one statement's transcript pass for another's. With length prefixes,
    different sequences of parts always encode differently.
    """
    return b"".join(len(part).to_bytes(4, "big") + part for part in parts)


def encode_int(value: int) -> bytes:
    """A non-negative integer below 2**256, as 32 big-endian bytes."""
    return value.to_bytes(32, "big")

"""Unit: canonical JSON stability (shared/canonical.py)."""
import pytest

from shared.canonical import canonical


def test_key_order_irrelevant():
    a = canonical({"z": 1, "a": [1, 2], "m": {"y": 1, "b": 2}})
    b = canonical({"m": {"b": 2, "y": 1}, "a": [1, 2], "z": 1})
    assert a == b


def test_separators_and_utf8():
    out = canonical({"name": "Adaeze ☀", "n": 1})
    assert out == '{"n":1,"name":"Adaeze ☀"}'.encode("utf-8")
    assert isinstance(out, bytes)


def test_floats_rejected_everywhere():
    with pytest.raises(TypeError):
        canonical({"exp": 1.5})
    with pytest.raises(TypeError):
        canonical([1, [2.0]])
    with pytest.raises(TypeError):
        canonical({"n": {" deep ": 0.1}})


def test_bool_int_none_allowed():
    assert canonical({"r": 1, "ok": True, "x": None}) == b'{"ok":true,"r":1,"x":null}'


def test_deterministic_vectors():
    assert canonical(["yn-proof-v1", "ab", "n", "SHOP-A", 5]) == \
        b'["yn-proof-v1","ab","n","SHOP-A",5]'

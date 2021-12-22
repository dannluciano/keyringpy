import json
import os
import pytest

from keyringpy.keyring import SHA1


def test_SHA1():
    expected = "92cfceb39d57d914ed8b14d0e37643de0797ae56"
    msg = "42"
    digest_salt = ""
    computed = SHA1(msg, digest_salt=digest_salt)

    assert expected == computed

def test_SHA1with_digest_salt():
    expected = "f0545c0631e99b6571dc2ef167778c5c472e09ad"
    msg = "42"
    digest_salt = "1mP*ofbm734B"
    computed = SHA1(msg, digest_salt=digest_salt)

    assert expected == computed

def test_SHA1_without_digest_salt():
    msg = "42"
    digest_salt = None
    with pytest.raises(Exception) as exception:
        computed = SHA1(msg, digest_salt)

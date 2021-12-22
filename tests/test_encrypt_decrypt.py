import json
import os
import pytest

from keyringpy.keyring import Keyring


def test_Keyring_encrypt():
    plain_msg = "42"
    digest_salt = ""
    keys = {"1": "7K0xBRrumkPm03UKS3g4MFm2gGCrFCa3eXnBWigOdlM="}
    encryptor = Keyring(keys, {"digest_salt": digest_salt})
    computed_encrypted, computed_key_id, computed_digest = encryptor.encrypt(plain_msg)

    expected_digest = "92cfceb39d57d914ed8b14d0e37643de0797ae56"
    expected_key_id = 1

    assert expected_digest == computed_digest
    assert expected_key_id == computed_key_id

def test_Keyring_decrypt():
    encrypted_msg = "UUXMN2NmF8703gNMawcecwgdfQRPUpXBWyGnlklwmGCU/oMKKQa9C41CyXiF6jT806GmZrM+Zql5QSYBy5H18A=="
    digest_salt = ""
    keys = {"1": "7K0xBRrumkPm03UKS3g4MFm2gGCrFCa3eXnBWigOdlM="}
    key_id = 1
    encryptor = Keyring(keys, {"digest_salt": digest_salt})
    computed_plain_msg = encryptor.decrypt(encrypted_msg, key_id)
    expected_plain_msg = "42"

    assert expected_plain_msg == computed_plain_msg

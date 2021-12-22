from hashlib import sha1
import base64
import hmac

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


default_keyring_options = {
    "encryption": "aes-128-cbc",
}

key_sizes = {
    "aes-128-cbc": 16,
    "aes-192-cbc": 24,
    "aes-256-cbc": 32,
}


def HMAC(key, msg=None):
    hmac_algo = hmac.new(key, digestmod='SHA256')
    hmac_algo.update(msg)
    return hmac_algo.digest()


def SHA1(msg, digest_salt=None):
    if digest_salt == None:
        raise Exception(
            "Please provide `digest_salt` option; you can disable this Exception by explicitly passing an empty string."
        )

    bin_digest_salt = digest_salt.encode()
    if isinstance(msg, str):
        msg = msg.encode()

    sha1_algo = sha1()
    sha1_algo.update(msg+bin_digest_salt)
    return sha1_algo.hexdigest()


def isNaN(num):
    return num != num


def key_buffer(value):
    if isinstance(value, bytes):
        return value

    return base64.b64decode(value.encode())


def normalize_keys(keys, key_size):
    expected_key_size = key_size * 2
    buffer = []
    for id in keys.keys():
        secret = key_buffer(keys[id])

        if len(secret) != expected_key_size:
            raise Exception(
                f"Expected key to be {expected_key_size} bytes long; got {len(secret)} instead"
            )

        signing_key = secret[0:key_size]
        encryption_key = secret[key_size:]

        buffer.append({
            'id': int(id, 10),
            'encryption_key': encryption_key,
            'signing_key': signing_key,
        })

    return buffer


def validate_keyring(keys):
    if len(keys) == 0:
        raise Exception("You must initialize the keyring")

    invalid_ids = []
    for key in keys:
        if isNaN(key['id']):
            invalid_ids.append(key)

    if (invalid_ids):
        raise Exception("All keyring keys must be integer numbers")


def signature_is_not_equal(expected, actual):
    accum = 0

    if len(expected) != len(actual):
        return true

    for i in range(0, len(expected)):
        accum |= expected[i] ^ actual[i]

    return not (accum == 0)


class Keyring:
    def __init__(self, keys={}, options={}):
        self._options = {**default_keyring_options, **options}

        if self._options['digest_salt'] == None:
            raise Exception(
                "Please provide `digest_salt` option; you can disable this Exception by explicitly passing an empty string."
            )

        encryption = self._options['encryption']
        key_size = key_sizes[encryption]

        if not key_size:
            raise Exception(f"Invalid encryption algorithm: {encryption}")

        self._keys = normalize_keys(keys, key_size)
        validate_keyring(self._keys)

    def _current_key(self):
        self._keys.sort(
            key=lambda key: key['id']
        )
        return self._keys[-1]

    def _findKey(self, id):
        key = list(filter(lambda key: key["id"] == id, self._keys))

        if key:
            return key[0]

        raise Exception(f"key={id} is not available on keyring")

    def encrypt(self, plain_msg):
        key = self._current_key()
        keyring_id = key['id']

        iv = get_random_bytes(16)

        bin_msg = plain_msg.encode()

        cipher = AES.new(key['encryption_key'], AES.MODE_CBC, iv=iv)
        encrypted_msg = cipher.encrypt(pad(bin_msg, AES.block_size))

        hmac_digest = HMAC(key['signing_key'], msg=iv+encrypted_msg)

        encrypted = base64.b64encode(
            hmac_digest+iv+encrypted_msg
        ).decode('utf-8')

        sha1_digest = SHA1(bin_msg, self._options['digest_salt'])

        return (encrypted, keyring_id, sha1_digest)

    def decrypt(self, encrypted_msg, keyring_id):
        decoded = base64.b64decode(encrypted_msg)
        hmac = decoded[0:32]
        iv = decoded[32:48]
        encrypted = decoded[48:]

        key = self._findKey(keyring_id)

        decipher = AES.new(key['encryption_key'], AES.MODE_CBC, iv=iv)

        decrypted = unpad(decipher.decrypt(encrypted), AES.block_size)

        expected_hmac = HMAC(key['signing_key'], msg=iv+encrypted)

        if signature_is_not_equal(expected_hmac, hmac):
            expected_hmac_64 = base64.b64encode(expected_hmac).decode()
            hmac_64 = base64.b64encode(hmac).decode()
            raise Exception(
                f"Expected HMAC to be \"{expected_hmac_64}\"; got \"{hmac_64}\" instead"
            )
        return decrypted.decode()

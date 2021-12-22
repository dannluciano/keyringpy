from keyring import Keyring;

keys = { '1': "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M=" }
encryptor = Keyring(keys, { "digest_salt": "salt-n-pepper" })

# STEP 1: Encrypt message using latest encryption key.
encrypted, keyringId, digest = encryptor.encrypt("super secret")
print(f'🔒 {encrypted}')
print(f'🔑 {keyringId}')
print(f'🔎 {digest}')
#=> 🔒 Vco48O95YC4jqj44MheY8zFO2NLMPp/KILiUGbKxHvAwLd2/AN+zUG650CJzogttqnF1cGMFb//Idg4+bXoRMQ==
#=> 🔑 1
#=> 🔎 c39ec9729dbacd45cecd5ea9a60b15b50b0cc857

# STEP 2: Decrypted message using encryption key defined by keyring id.
decrypted = encryptor.decrypt(encrypted, keyringId)
print(f'✉️ {decrypted}')
#=> ✉️ super secret
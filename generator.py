# import os
# print (os.urandom(16))
# salt = b'\x11\xe9\x83Q\x9b\xe0Vj\xe1\xc0\x1b\x05\xf5\xd7\r*' # This is for alice
# salt = b'^\xf8_\xfb\xc8\xb7\x15N\xb6\x11\xa6\x14\x8b4\x1b\x13' # This is for bob
salt = b'7\x8c\xb8\x17\xbf\x8e\xbd\xe3\xd8\x9a\xd85\x1a\xf3c1'

password = "abcd1234"
salt = salt.hex()
print (salt)
from argon2 import low_level

verifier = low_level.hash_secret_raw(
        secret=password.encode(),
        salt=bytes.fromhex(salt),
        time_cost=3,        # 3 iterations
        memory_cost=65536,  # 64MB (65536 KB)
        parallelism=4,      # 4 threads
        hash_len=32,        # 32-byte output
        type=low_level.Type.ID
    )
print(verifier.hex())

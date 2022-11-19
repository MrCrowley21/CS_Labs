import binascii
import secrets
import argon2
from string_transformer import *


class PasswordHashing:
    # hash the data
    def hash_password(self, password):
        # generate the salt using cryptographic secure random, secure
        salt = b'\x00' + secrets.token_bytes(32) + b'\x00'
        hashing = argon2.hash_password(time_cost=16, memory_cost=2 ** 15, parallelism=2, hash_len=32,
                                       password=bytes(password, encoding='utf-8'), salt=salt,
                                       type=argon2.low_level.Type.ID)
        hashed_password = binascii.hexlify(hashing)
        return salt, hashed_password

    # verify the password
    def verify_password(self, password, salt, hashed_password):
        hashing = argon2.hash_password(time_cost=16, memory_cost=2 ** 15, parallelism=2, hash_len=32,
                                               password=bytes(password, encoding='utf-8'), salt=salt,
                                               type=argon2.low_level.Type.ID)
        current_hashed_password = binascii.hexlify(hashing)
        # compare hashes
        if hashed_password == current_hashed_password:
            return True
        else:
            return False

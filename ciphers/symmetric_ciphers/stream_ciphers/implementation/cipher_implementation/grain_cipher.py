import numpy as np

from implementation.string_transformer import *


class GrainCipher:
    def __init__(self):
        self.key, self.iv, self.text = self.__get_input_data()
        self.lfsr = np.zeros(80, dtype=bool)  # the 80-bit linear feedback shift register
        self.nfsr = np.zeros(80, dtype=bool)  # the 80-bit non-linear feedback shift  register
        self.transformer = StringTransformer()  # initiation of class transforming text to binary form and vice-versa

    # get the key, iv and the text to be encrypted or decrypted
    def __get_input_data(self):
        print('Input the key. Its length must be exactly 10 characters')
        key = input()
        # check the rightfulness of the keyword input
        if len(key) != 10:
            raise Exception('Keyword must have the length exactly 10')
        print('Input the iv. Its length must be exactly 8 characters')
        iv = input()
        # check the rightfulness of the keyword input
        if len(iv) != 8:
            raise Exception('Keyword must have the length exactly 8')
        print('Input the text you want to be encrypted or decrypted:')
        text = input()
        return key, iv, text

    # initiate the LFSR and NLFSR
    def __initiate_lfsr_nfsr(self):
        # transform key and iv in binary form
        binary_iv = self.transformer.convert_text_to_bit(self.iv)
        binary_key = self.transformer.convert_text_to_bit(self.key)
        binary_iv_len = len(binary_iv)
        binary_key_len = len(binary_key)
        # initiate the LFSR with iv; the remaining spaces fill with 1's
        self.lfsr[:64] = [bool(int(binary_iv[i])) for i in range(binary_iv_len)]
        self.lfsr[64:] = 1
        # initiate the NFLSR with key
        self.nfsr[:] = [bool(int(binary_key[i])) for i in range(binary_key_len)]

    # shift the LFSR and NLFSR and get the output of the filter function
    def __update_register(self, fx, gx):
        # initiate bits for filter function updating
        x0 = self.lfsr[0]
        x1 = self.lfsr[25]
        x2 = self.lfsr[46]
        x3 = self.lfsr[64]
        x4 = self.nfsr[63]
        # update filter function
        hx = x1 ^ x4 ^ x0 & x3 ^ x2 & x3 ^ x3 & x3 ^ x0 & x1 & x2 ^ x0 & x2 & x3 ^ \
            x0 & x2 & x4 ^ x1 & x2 & x4 ^ x2 & x3 & x4
        # shift LFSR nd NLFSR by one bit left
        self.lfsr[:-1] = self.lfsr[1:]
        self.nfsr[:-1] = self.nfsr[1:]
        self.lfsr[-1] = fx
        self.nfsr[-1] = gx
        return hx

    # initialize the cipher
    def __clock(self):
        # set the filter function to feed the feedback to LFSR and NLFSR updating ciphers
        hx = 0
        for i in range(160):
            # feed-back the LFSR updating function
            fx = self.lfsr[62] ^ self.lfsr[51] ^ self.lfsr[38] ^ self.lfsr[23] ^ \
                 self.lfsr[13] ^ self.lfsr[0] ^ hx
            # feed-back the NLFSR updating function
            gx = hx ^ self.nfsr[0] ^ self.nfsr[63] ^ self.nfsr[60] ^ self.nfsr[52] ^ self.nfsr[45] ^ self.nfsr[37] ^ \
                self.nfsr[33] ^ self.nfsr[28] ^ self.nfsr[21] ^ self.nfsr[15] ^ self.nfsr[19] ^ self.nfsr[0] ^ \
                self.nfsr[63] & self.nfsr[60] ^ self.nfsr[37] & self.nfsr[33] ^ self.nfsr[15] & self.nfsr[9] ^ \
                self.nfsr[60] & self.nfsr[52] & self.nfsr[45] ^ self.nfsr[33] & self.nfsr[28] & self.nfsr[21] ^ \
                self.nfsr[63] & self.nfsr[45] & self.nfsr[28] & self.nfsr[9] ^ self.nfsr[60] & self.nfsr[52] & \
                self.nfsr[37] & self.nfsr[33] ^ self.nfsr[63] & self.nfsr[60] & self.nfsr[21] & self.nfsr[15] ^ \
                self.nfsr[63] & self.nfsr[60] & self.nfsr[52] & self.nfsr[45] & self.nfsr[37] ^ self.nfsr[33] & \
                self.nfsr[28] & self.nfsr[21] & self.nfsr[15] & self.nfsr[9] ^ self.nfsr[52] & self.nfsr[45] & \
                self.nfsr[37] & self.nfsr[33] & self.nfsr[28] & self.nfsr[21]
            # update keystream generator
            hx = self.__update_register(fx, gx)

    # generate the keystream for the encryption/decryption process
    def __generate_key_stream(self):
        while True:
            # update LFSR updating function
            fx = self.lfsr[62] ^ self.lfsr[51] ^ self.lfsr[38] ^ self.lfsr[23] ^ \
                 self.lfsr[13] ^ self.lfsr[0]
            # update NLFSR updating function
            gx = self.nfsr[0] ^ self.nfsr[63] ^ self.nfsr[60] ^ self.nfsr[52] ^ self.nfsr[45] ^ self.nfsr[37] ^ \
                self.nfsr[33] ^ self.nfsr[28] ^ self.nfsr[21] ^ self.nfsr[15] ^ self.nfsr[19] ^ self.nfsr[0] ^ \
                self.nfsr[63] & self.nfsr[60] ^ self.nfsr[37] & self.nfsr[33] ^ self.nfsr[15] & self.nfsr[9] ^ \
                self.nfsr[60] & self.nfsr[52] & self.nfsr[45] ^ self.nfsr[33] & self.nfsr[28] & self.nfsr[21] ^ \
                self.nfsr[63] & self.nfsr[45] & self.nfsr[28] & self.nfsr[9] ^ self.nfsr[60] & self.nfsr[52] & \
                self.nfsr[37] & self.nfsr[33] ^ self.nfsr[63] & self.nfsr[60] & self.nfsr[21] & self.nfsr[15] ^ \
                self.nfsr[63] & self.nfsr[60] & self.nfsr[52] & self.nfsr[45] & self.nfsr[37] ^ self.nfsr[33] & \
                self.nfsr[28] & self.nfsr[21] & self.nfsr[15] & self.nfsr[9] ^ self.nfsr[52] & self.nfsr[45] & \
                self.nfsr[37] & self.nfsr[33] & self.nfsr[28] & self.nfsr[21]
            # update keystream generator and get the new stream
            hx = self.__update_register(fx, gx)
            yield hx

    # encrypt the text
    def encrypt_text(self):
        text = self.transformer.convert_text_to_bit(self.text)
        self.__initiate_lfsr_nfsr()
        self.__clock()
        stream = self.__generate_key_stream()
        # xor bits of the text with the stream
        encrypted_text = [str(int(bool(int(text[i])) ^ next(stream))) for i in range(len(text))]
        encrypted_text = ''.join(encrypted_text)
        return encrypted_text

    # decrypt the text
    def decrypt_text(self):
        self.__initiate_lfsr_nfsr()
        self.__clock()
        stream = self.__generate_key_stream()
        # xor bits of the text with the stream
        decrypted_text = [str(int(bool(int(self.text[i])) ^ next(stream))) for i in range(len(self.text))]
        decrypted_text = ''.join(decrypted_text)
        # transform binary text into normal form
        try:
            decrypted_text = self.transformer.convert_bit_to_text(decrypted_text)
        except:
            raise Exception(f'It seems the given data is incorrect')
        return decrypted_text

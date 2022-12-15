from string_transformer import *
from ciphers.symmetric_ciphers.stream_ciphers.implementation.utils import *


class DESCipher:
    def __init__(self, key, text):
        # this line is for non-server version
        # self.key, self.text = self.__get_input_data()
        self.key = key
        self.text = text
        self.nr_zero_addition = 0  # nr of added zeros to complete the block
        self.transformer = StringTransformer()  # initiation of class transforming text to binary form and vice-versa

    # get the key and the text to be encrypted or decrypted
    # this function is for non-server version
    # def __get_input_data(self):
    #     print('Input the key. Its length must be exactly 8 characters')
    #     key = input()
    #     if len(key) != 8:
    #         raise Exception('The key must be of size 8')
    #     print('Input the text you want to be encrypted or decrypted:')
    #     text = input()
    #     return key, text

    # get the zero additions for decryption
    def __get_nr_zero_addition(self):
        print('Input the number of additional appended zeros')
        try:
            self.nr_zero_addition = int(input())
        except:
            raise Exception('Number of added zeros must be an integer')

    # group the binary text in blocks of 64 bits (complete with 0's if necessary)
    def __group_in_blocks(self, block):
        block_list = []
        zero_counter = 0
        # fill smaller boxes with 0's
        if len(block) % 64 != 0:
            for i in range(64 - (len(block) % 64)):
                zero_counter += 1
                block += '0'
        # Make blocks and append them to the block list
        for i in range(len(block) // 64):
            block_list.append(block[i * 64: i * 64 + 64])
        return block_list, zero_counter

    # Replace bits in input block according to the given permutation
    def __replace_block(self, block, box):
        initial_replaced_block = ''
        for i in box:
            try:
                initial_replaced_block += block[i - 1]
            except IndexError:
                raise Exception(f'Cannot access index {i - 1} in {block} with the length: {len(block)}')
        return initial_replaced_block

    # replace block according to the initial permutation
    def __replace_block_initial(self, block):
        return self.__replace_block(block, INITIAL_PERMUT)

    # extend 32-bit block (half of original) to 48-bit block to get the confusion
    def __extend_e_box(self, block):
        extended_block = ''
        for i in E_BOX:
            extended_block += block[i - 1]
        return extended_block

    # compress the 48-bit block into 32-bit block
    def __compress_s_box(self, block, encoding='utf-8', errors='surrogatepass'):
        result = ''
        # get blocks by 4, instead of 6
        for i in range(8):
            # find the row to be compressed
            binary_row = (block[i * 6] + block[i * 6 + 5]).encode(encoding, errors)
            binary_line = (block[i * 6 + 1: i * 6 + 5]).encode(encoding, errors)
            decimal_row = int(binary_row, 2)
            decimal_line = int(binary_line, 2)
            # compress the raw
            compressed = S_BOX[i][decimal_row][decimal_line]
            compressed_binary = str(bin(compressed))[2:]
            while len(compressed_binary) < 4:
                compressed_binary = '0' + compressed_binary
            result += compressed_binary
        return result

    # replace bits according to the P-BOX block
    def __replace_p_box(self, block):
        return self.__replace_block(block, P_BOX)

    # describes xoring bits opperation
    def __get_xored_result(self, string_1, string_2):
        result = ''
        for i in range(len(string_2)):
            if string_1[i] == string_2[i]:
                result += '0'
            else:
                result += '1'
        return result

    # perform f function
    def __get_f_function(self, right, subkey):
        # apply e-box extension
        extended_right = self.__extend_e_box(right)
        # xor with subkeys
        xored_right = self.__get_xored_result(extended_right, subkey)
        # get S-box compression
        s_compressed_result = self.__compress_s_box(xored_right)
        # get P-box replacement
        result = self.__replace_p_box(s_compressed_result)
        return result

    # pass 16-bit encryption and define halves of blocks
    def __round_iterate(self, block, subkeys):
        for i in range(16):
            left, next_left, right = block[0:32], block[32:64], block[32:64]
            f_result = self.__get_f_function(right, subkeys[i])
            right = self.__get_xored_result(left, f_result)
            block = next_left + right
        return block[32:] + block[:32]

    def __reduce_key(self, key):
        return self.__replace_block(key, REDUCED_KEY)

    def __get_subkeys(self, key):
        subkeys = []
        compressed_key = self.__reduce_key(key)
        left, right = compressed_key[0: 28], compressed_key[28: 56]
        for i in range(16):
            left_spin = left[ROUND[i]:] + left[:ROUND[i]]
            right_spin = right[ROUND[i]:] + right[:ROUND[i]]
            subkeys.append(left_spin + right_spin)
        return subkeys

    def __compress_subkey(self, subkeys):
        compressed_subkeys = []
        for subkey in subkeys:
            compressed_subkeys.append(self.__replace_block(subkey, SUBKEY_BOX))
        return compressed_subkeys

    def __get_compressed_subkeys(self, key, is_encryption=False):
        binary_key = self.__group_in_blocks(key)[0][0]
        if is_encryption:
            subkeys = self.__get_subkeys(binary_key)
        else:
            subkeys = self.__get_subkeys(binary_key)[::-1]
        compressed_subkeys = self.__compress_subkey(subkeys)
        return compressed_subkeys

    def __replace_final_block(self, block):
        return self.__replace_block(block, FINAL_PERMUT)

    def __get_encrypt_decrypt_algorithm(self, blocks, key, is_encryption):
        result = ''
        compressed_subkeys = self.__get_compressed_subkeys(key, is_encryption)
        for block in blocks:
            initial_result = self.__replace_block_initial(block)
            block_result = self.__round_iterate(initial_result, compressed_subkeys)
            block_result = self.__replace_final_block(block_result)
            result += block_result
        return result

    def encrypt_text(self):
        binary_text = self.transformer.convert_text_to_bit(self.text)
        key = self.transformer.convert_text_to_bit(self.key)
        blocks, nr_zero_addition = self.__group_in_blocks(binary_text)
        encrypted_text = self.__get_encrypt_decrypt_algorithm(blocks, key, True)
        return f'Encrypted text: {encrypted_text} Nr of additional zeros: {nr_zero_addition}'

    def decrypt_text(self):
        self.__get_nr_zero_addition()
        blocks = self.__group_in_blocks(self.text)[0]
        key = self.transformer.convert_text_to_bit(self.key)
        binary_decrypted_text = self.__get_encrypt_decrypt_algorithm(blocks, key, False)
        if self.nr_zero_addition > 0:
            binary_decrypted_text = binary_decrypted_text[:-self.nr_zero_addition]
        try:
            decrypted_text = self.transformer.convert_bit_to_text(binary_decrypted_text)
        except:
            raise Exception(f'I seems the given data is incorrect')
        return decrypted_text

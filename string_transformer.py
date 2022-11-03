class StringTransformer:
    # convert text to bit
    def convert_text_to_bit(self, input_string, encoding='utf-8'):
        binary_text = ''.join(format(i, '08b') for i in bytearray(input_string, encoding))
        return binary_text

    # convert text to integer
    def convert_text_to_int(self, input_string, encoding ='utf-8'):
        encoded_text = input_string.encode('utf-8')
        int_string = int(encoded_text.hex(), 16)
        return int_string

    # convert bit ot text
    def convert_bit_to_text(self, binary_string, encoding='utf-8', errors='surrogatepass'):
        decimal_binary_value = int(binary_string, 2)
        nr_byte = decimal_binary_value.bit_length() + 7 // 8
        binary_array = decimal_binary_value.to_bytes(nr_byte, 'big')
        return binary_array.decode(encoding, errors)

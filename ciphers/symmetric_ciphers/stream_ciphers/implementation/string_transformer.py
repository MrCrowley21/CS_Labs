class StringTransformer:
    def convert_text_to_bit(self, input_string, encoding='utf-8'):
        binary_text = ''.join(format(i, '08b') for i in bytearray(input_string, encoding))
        return binary_text

    def convert_bit_to_text(self, binary_string, encoding='utf-8', errors='surrogatepass'):
        decimal_binary_value = int(binary_string, 2)
        nr_byte = decimal_binary_value.bit_length() + 7 // 8
        binary_array = decimal_binary_value.to_bytes(nr_byte, 'big')
        return binary_array.decode(encoding, errors)

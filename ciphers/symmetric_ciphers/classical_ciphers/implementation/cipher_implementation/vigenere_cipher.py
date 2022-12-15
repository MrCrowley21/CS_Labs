class VigenereCipher:
    def __init__(self, keyword, word):
        # this line is for non-server version
        # self.keyword, self.word = self.__get_input_data()
        self.keyword = keyword
        self.word = word
        self.normal_alphabet = [chr(i) for i in range(65, 91)]  # english alphabet in the correct order

    # get the keyword and the text to be encrypted or decrypted
    # this function is for non-server version
    # def __get_input_data(self):
    #     print('Input the keyword. It must contain only latin letters and blank '
    #           'spaces:')
    #     keyword = input()
    #     # check the rightfulness of the keyword input
    #     if not all(x.isalpha() or x.isspace() for x in keyword):
    #         raise Exception('Keyword should contain only latin letters and blank spaces')
    #     print('Input the text you want to be encrypted or decrypted:')
    #     word = input()
    #     # check the rightfulness of the word input
    #     if not all(x.isalpha() or x.isspace() for x in word):
    #         raise Exception('The text should contain only latin letters and blank spaces')
    #     return keyword, word

    # make uppercase all letters in the input word and remove spaces
    def __set_word(self, word):
        word = word.upper()
        word = word.replace(' ', '')
        return word

    # encrypt the text
    def encrypt_text(self):
        self.word = self.__set_word(self.word)
        self.keyword = self.__set_word(self.keyword)
        keyword_length = len(self.keyword)
        encoded_text = ''
        k = 0
        for i in self.word:
            # set the row index as current letter index from the word
            word_letter_index = self.normal_alphabet.index(i)
            # set the column index as current letter index from the keyword
            keyword_letter_index = self.normal_alphabet.index(self.keyword[k % keyword_length])
            # get the letter using the formula
            encoded_text += self.normal_alphabet[(word_letter_index + keyword_letter_index) % 26]
            k += 1
        return encoded_text

    # decrypt the text
    def decrypt_text(self):
        self.word = self.__set_word(self.word)
        self.keyword = self.__set_word(self.keyword)
        keyword_length = len(self.keyword)
        decoded_text = ''
        k = 0
        for i in self.word:
            # set the row index as current letter index from the word
            word_letter_index = self.normal_alphabet.index(i)
            # set the column index as current letter index from the keyword
            keyword_letter_index = self.normal_alphabet.index(self.keyword[k % keyword_length])
            # get the letter using the formula
            decoded_text += self.normal_alphabet[(word_letter_index - keyword_letter_index + 26) % 26]
            k += 1
        return decoded_text

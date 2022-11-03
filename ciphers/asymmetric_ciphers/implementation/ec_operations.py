import libnum


class EllipticCurveOperations:

    # perform the extended Euclidean Algorithm
    def __gcd_extended(self, a, b):
        if a == 0:
            return b, 0, 1
        else:
            while a < 0:
                a += b
            gcd, y, x = self.__gcd_extended(b % a, a)
            return gcd, x - (b // a) * y, y

    # get the modular inverse
    def __get_modular_inverse(self, a, mod):
        gcd_result, x, y = self.__gcd_extended(a, mod)
        # check if valid number input
        if gcd_result != 1:
            raise Exception(f'Inverse of {a} in this curve field does not exist')
        else:
            inverse = x % mod
            while inverse < 0:
                inverse += mod
        return inverse

    # addition of elliptic curve points
    def add_points(self, x1, y1, x2, y2, a, mod):
        # if double the original point
        if x1 == x2 and y1 == y2:
            temp = (3 * x1 ** 2 + a) * (self.__get_modular_inverse(2 * y1, mod))
        else:
            temp = (y2 - y1) * (self.__get_modular_inverse((x2 - x1), mod))

        result_x = temp ** 2 - x2 - x1
        result_y = temp * (x2 - result_x) - y2

        result_x = result_x % mod
        result_y = result_y % mod

        while result_x < 0:
            result_x += mod
        while result_y < 0:
            result_y += mod

        return result_x, result_y

    # apply Double and add algorithm
    def apply_double_addition_algorithm(self, x, y, k, a, mod):
        temp_x = x
        temp_y = y
        # delete base marks
        k = k[2:len(k)]
        for i in range(1, len(k)):
            current_bit = k[i]
            # double the point
            temp_x, temp_y = self.add_points(temp_x, temp_y, temp_x, temp_y, a, mod)
            # add in case of 1s
            if current_bit == '1':
                temp_x, temp_y = self.add_points(temp_x, temp_y, x, y, a, mod)
        return temp_x, temp_y

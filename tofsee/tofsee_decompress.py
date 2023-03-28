def decompress(data, size):
    def core(acu_0, acu_1, array, index):
        tmp_acu_1 = acu_1
        acu_1 = acu_1 - 1 & 0xFFFFFFFF

        if tmp_acu_1 == 0:
            acu_0 = ((array[index + 1] << 8) + array[index]) & 0xFFFFFFFF
            acu_1 = 0xF
            index += 2

        tmp_arg_0 = acu_0
        acu_0 = (2 * acu_0) & 0xFFFFFFFF
        return tmp_arg_0 >> 0xF & 0x1, acu_0, acu_1, index

    result = bytes([data[0]])
    i = 1
    var_0 = 0
    var_1 = 0

    while len(result) != size:
        flag, var_0, var_1, i = core(var_0, var_1, data, i)
        j = 1

        if flag == 0:
            result += bytes([data[i]])
            i += 1
        else:
            while True:
                flag, var_0, var_1, i = core(var_0, var_1, data, i)
                j = flag + 2 * j
                flag, var_0, var_1, i = core(var_0, var_1, data, i)

                if flag == 0:
                    break

            j += 2
            k = 1

            while True:
                flag, var_0, var_1, i = core(var_0, var_1, data, i)
                k = flag + 2 * k
                flag, var_0, var_1, i = core(var_0, var_1, data, i)

                if flag == 0:
                    break

            for _ in range(0, j):
                result += bytes([result[len(result) - (data[i] + ((k + 0xFFFFFFFE) << 8) + 1) & 0xFFFFFFFF]])
            i += 1

    return result
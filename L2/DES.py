import codecs
import math
from hashlib import sha512

SBox_matrix = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


def left_shift(seq: str):
    return seq[1:] + seq[0]


def right_shift(seq: str):
    return seq[-1] + seq[:-1]


def generate_round_key(initial_key, round: int):
    shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    initial_permutation = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    ]
    expanded_key = ""
    for i in range(8):
        ones = 0
        for j in range(7):
            expanded_key += str(initial_key)
            ones += 1
        expanded_key += str((ones + 1) % 2)

    permuted = ''.join([expanded_key[item] for item in initial_permutation])

    c0 = permuted[:14]
    d0 = permuted[14:]
    for i in range(round):
        for l in range(shift_table[i]):
            c0 = left_shift(c0)
            d0 = left_shift(d0)
    res_key = c0 + d0

    picked_bits = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]

    return ''.join([res_key[item - 1] for item in picked_bits])


def substitute(bit_sequence: str, sequence_no: int) -> str:
    row = int(bit_sequence[0] + bit_sequence[-1], base=2)
    col = int(bit_sequence[1:5], base=2)
    binary = intTo8BitBin(SBox_matrix[sequence_no][row][col])[4:]
    return binary


def expand(bit_seq):
    expansion_matrix = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    res = ""
    assert len(bit_seq) == 32
    for i in expansion_matrix:
        res += str(bit_seq[i - 1])
    return res


def permute(bit_seq):
    feistel_permutation = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    res = ""
    for i in feistel_permutation:
        res += str(bit_seq[i - 1])

    return res


def feistel_func(r, k, encoding_round):
    expanded = expand(r)
    key = generate_round_key(k, encoding_round)
    summed_with_key = ''.join([str(int(i) ^ int(j)) for i, j in zip(expanded, key)])
    after_sub = ''.join([substitute(summed_with_key[i:i + 6], i // 6) for i in range(0, 48, 6)])
    result = permute(after_sub)
    return result


def encrypt_block(message, key):
    if len(key) < 7:
        raise Exception
    key = key[:7]
    sha_key = ""
    for item in key:
        sha_key += intTo8BitBin(ord(item))
    # sha_key = sha512(bytes(str(key), "utf-8")).hexdigest()[:14]
    # sha_key = bin(int(sha_key, base=16))[2:]

    print(sha_key)
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]

    message = "".join([message[item - 1] for item in IP])

    Li = message[:32]
    Ri = message[32:]

    for i in range(16):
        L_new = Ri
        R_new = [int(r) ^ int(k) for r, k in zip(Li, feistel_func(Ri, sha_key, i))]
        Ri = R_new
        Li = L_new

    encrypted = Li + Ri

    InverseIP = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]

    encrypted = "".join([str(encrypted[item - 1]) for item in InverseIP])
    return hex(int(encrypted, base=2))[2:]


def decrypt_block(encrypted, key):
    if len(key) < 7:
        raise Exception
    key = key[:7]
    sha_key = ""
    for item in key:
        sha_key += intTo8BitBin(ord(item))

    # sha_key = sha512(bytes(str(key), "utf-8")).hexdigest()[:14]
    # sha_key = bin(int(sha_key, base=16))[2:]

    IP = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]

    encrypted = "".join([encrypted[item - 1] for item in IP])

    Li = encrypted[:32]
    Ri = encrypted[32:]

    for i in range(15, -1, -1):
        R_new = Li
        L_new = [int(r) ^ int(k) for r, k in zip(Ri, feistel_func(Li, sha_key, i))]
        Ri = R_new
        Li = L_new

    message = Li + Ri

    InverseIP = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]

    message = "".join([str(message[item - 1]) for item in InverseIP])

    return message


def intTo8BitBin(num: int):
    binary = bin(num)[2:]
    return "0" * (8 - len(binary)) + binary


def encrypt(message, key):
    message_coded = "".join([intTo8BitBin(num) for num in codecs.encode(message)])
    blocks = []
    i = 0
    bl_cnt = 0
    while i + 64 <= len(message_coded):
        blocks.append(message_coded[i:i + 64])
        bl_cnt += 1
        i += 64

    if i != len(message_coded):
        blocks.append(message_coded[i:] + "0" * (math.ceil(len(message_coded) / 64) * 64 - i))

    encrypted = []
    for block in blocks:
        encrypted.append(encrypt_block(block, key))
    return "".join(encrypted)


def decrypt(encrypted_message, key):
    encrypted_blocks = [encrypted_message[i:i + 16] for i in range(0, len(encrypted_message), 16)]
    decrypted = []
    for block in encrypted_blocks:
        block = bin(int(block, base=16))[2:]
        block = "0" * (64 - len(block)) + block
        decrypted.append(decrypt_block(block, key))

    decrypted = "".join(decrypted)
    blocks = 0
    for i in range(len(decrypted) - 8, -1, -8):
        if decrypted[i: i + 8] == "0" * 8:
            blocks += 1
        else:
            break

    decrypted = decrypted[:len(decrypted) - 8 * blocks]

    decrypted = bytes([int(decrypted[i:i + 8], base=2) for i in range(0, len(decrypted), 8)])

    return codecs.decode(decrypted)


print(decrypt(encrypt("123", "abcdefg"), "abcdefg"))

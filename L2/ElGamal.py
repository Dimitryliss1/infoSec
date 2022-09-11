from __future__ import annotations

import base64
import json
import random


def eratosphenes(start, n: int):
    grid = [0]*(n + 1)
    grid[0] = 1
    grid[1] = 1
    result = set()
    for index, i in enumerate(grid):
        if i == 0:
            j = index
            if index >= start:
                result.add(j)
            while j <= n:
                grid[j] = 1
                j += index
    return list(result)


def gcd(n1, n2):
    while n1 != 0 and n2 != 0:
        if n1 >= n2:
            n1 %= n2
        else:
            n2 %= n1
    return n1 or n2


def powmod(a, b, p):
    res = 1
    while b:
        if b & 1:
            res = res * a % p
            b -= 1
        else:
            a = a * a % p
            b >>= 1
    return res


def generator(p):
    fact = []
    phi = p - 1
    n = phi
    i = 2
    while i * i <= n:
        if n % i == 0:
            fact.append(i)
            while n % i == 0:
                n //= i
        i += 1

    if n > 1:
        fact.append(n)

    for res in range(2, p + 1):
        ok = True
        i = 0
        while i < len(fact) and ok:
            ok &= (powmod(res, phi // fact[i], p) != 1)
            i += 1
        if ok:
            return res
    return -1


class ElGamal:
    def __init__(self):
        primes = eratosphenes(256, 1000)
        while True:
            self.p = random.choice(primes)
            if generator(self.p) == -1:
                continue
            else:
                self.g = generator(self.p)
                self.x = random.randint(1, self.p - 1)
                self.y = powmod(self.g, self.x, self.p)
                break

    def get_public_key(self):
        return {
            'y': self.y,
            'g': self.g,
            'p': self.p
        }

    def _get_session_key(self, p: int):
        possible = []
        for i in range(2, p - 1):
            if gcd(i, p - 1) == 1:
                possible.append(i)
        return random.choice(possible)

    def _encrypt(self, message: int, key: dict):
        p = key['p']
        assert message < p
        y = key['y']
        g = key['g']
        session_key = self._get_session_key(p)
        a = powmod(g, session_key, p)
        b = pow(y, session_key) * message % p
        return a, b

    def encrypt(self, message: str, key: dict):
        res = []
        for i in message.encode("utf-8"):
            res.append(self._encrypt(i, key))
        return str(base64.b64encode(bytes(json.dumps(res), 'utf-8')), 'utf-8')

    def _decrypt(self, cipher: tuple[int, int] | list[int, int]):
        a = cipher[0]
        b = cipher[1]
        return b * pow(a, self.p - 1 - self.x) % self.p

    def decrypt(self, text: str):
        ciphers = json.loads(base64.b64decode(bytes(text, 'utf-8')))
        res = bytearray()
        for i in ciphers:
            res.append(self._decrypt(i))

        return res.decode('utf-8')


item = ElGamal()
message = "Hello, world!"
print(message)
print()

cipher = item.encrypt(message, item.get_public_key())
print(cipher)
print(str(base64.b64decode(bytes(cipher, 'utf-8')), 'utf-8'))

print()
print(item.decrypt(cipher))

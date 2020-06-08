"""
Domain Parameters for 512-Bit Curves
# https://tools.ietf.org/html/rfc5639#page-14
"""
import random

# Elliptic curve Diffie-Hellman key exchange
class ECDH:
    p = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3

    A = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA

    B = 0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723

    x = 0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822

    y = 0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892

    q = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069

    def __init__(self):
        self.k_pr = random.randrange(2, self.q-1)

    # extended GCD algorithm
    def x_gcd(self, a, b):
        """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            (q, a), b = divmod(b, a), a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return b, x0, y0

    # multiplicative inverse mod n
    def mod_inv(self, a, n):
        g, x, y = self.x_gcd(a, n)
        if g != 1:
            raise ValueError(f'mod_inv for {a} does not exist')
        return x % n

    def get_s(self, a, p, x1, x2, y1, y2):
        if x1 == x2 and y1 == y2:
            s = ((x1**2 * 3 + a ) * self.mod_inv(2 * y1, p)) % p
        else:
            de = x2 - x1
            while de < 0:
                de += p
            s = ((y2 - y1) * self.mod_inv(de, p)) % p
        #print('s =', s)
        return s

    def verify(self, x, y, a, b, p):
        return (y**2 % p) == ((x**3 + a * x + b) % p)

    def elli_add(self, a, p, x1, y1, x2, y2):
        if (-y1) % p == y2 and x1 == x2:  # neutral element
            return 'neutral', 'element'
        else:
            s = self.get_s(a, p, x1, x2, y1, y2)
            x3 = (s ** 2 - x1 - x2) % p
            y3 = (s * (x1 - x3) - y1) % p
            return x3, y3

    def double_and_add(self, a, p, x, y, n):
        d = bin(n)[3:]  # remove '0b', start from the second bit
        xt, yt = x, y
        for i in d:
            xt, yt = self.elli_add(a, p, xt, yt, xt, yt)
            if i == '1':
                xt, yt = self.elli_add(a, p, xt, yt, x, y)
        return xt, yt

    def pub_key(self):
        return self.double_and_add(self.A, self.p, self.x, self.y, self.k_pr)

    def agreed_key(self, point):
        return self.double_and_add(self.A, self.p, point[0], point[1], self.k_pr)

if __name__ == '__main__':
    Alice = ECDH()
    A = Alice.pub_key()
    Bob = ECDH()
    B = Bob.pub_key()
    print(Alice.agreed_key(B)[0] == Bob.agreed_key(A)[0])  # only use x


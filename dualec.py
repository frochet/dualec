#!/usr/bin/env python

from __future__ import print_function
from random import randint
from sys import argv, stdout

from fastecdsa.curve import P256
from fastecdsa.point import Point

from mathutil import p256_mod_sqrt, mod_inv

def take30bytes(x):
    return x & (2**(8*30)-1)

class DualEC():
    def __init__(self, seed, P, Q):
        self.seed = seed
        self.P = P
        self.Q = Q

    def genbits(self):
        """Returns a pseudo-random integer of 30 bytes"""
        t = self.seed
        s = (t * self.P).x
        self.seed = s
        r = (s * self.Q).x
        return take30bytes(r)  # return 30 bytes


def backdoor_sanity_check(P, Q, d):
    # Verify that we have the backdoor (i.e P == d*Q)
    assert(d * Q == P)


def find_point_on_p256(x):
    """If x is such that there exists a point (x, y) on the curve P256, then
    return that point. Otherwise, return None."""
    # equation: y^2 = x^3-ax+b
    y2 = (x * x * x) - (3 * x) + P256.b
    y2 = y2 % P256.p
    y = p256_mod_sqrt(y2)
    if y2 == (y * y) % P256.p:
        return Point(x, y, curve=P256)
    else:
        return None


def gen_backdoor():
    """Generate backdored Dual EC parameters P = d*Q."""
    P = P256.G  # dual EC says set P to P256 base point
    d = randint(2, P256.q)  # pick a number that is in the field P256 is over

    # You may find the function mod_inv (from file mathutil.py) useful; P256.q
    # is the (prime) number of points in the curve.
    e = mod_inv(d, P256.q)  # find inverse of the number in the field of the base points order
    Q = e * P  # note that mult operator is overriden, this is multiplication on P256

    backdoor_sanity_check(P, Q, d)

    print('P = ({:x}, {:x})'.format(P.x, P.y))
    print('Q = ({:x}, {:x})'.format(Q.x, Q.y))
    print('d = {:x}'.format(d))

    return P, Q, d

def take26bytes(next_output):
    return next_output & 2**(8*26)-1

def take4MSBytes(next_output):
    return next_output >> (8*26)

def gen_prediction(observed1, observed2, P, Q, d):
    """Given a 34 bytes observation of the output of the backdored (P, Q, d)
    dual EC generator, predict the next 26 bytes of output.
    """
    for high_bits in range(2**16):
        # Set the 16 most significant bits to the guess value
        guess = (high_bits << (8 * 30)) | observed1

        # You may find the following functions to be useful:
        # find_point_on_p256, take26bytes, take4MSBytes
        point = find_point_on_p256(guess)
        if point is not None:
            # Use the backdoor to guess the next 30 bytes.
            # Let `observed` be 30 bytes of (((s0*P).x)*Q).x  = (s1*Q).x followed by two bytes
            # of ((((s0*P).x*P).x)*Q).x = (((s1*P).x)*Q).x = (s2*Q).x,
            # then `point` is (if our guess is correct) ((s0*P).x)*Q = s1*Q
            # and state is (d*s1*Q).x = (s1*P).x = s2.
            # We can thus compute the first two bytes of (state*Q).x and
            # compare it with the observation.
            state = (d*point).x
            next_output = take30bytes((state*Q).x)
            if take4MSBytes(next_output) == observed2:
                return take26bytes(next_output)

    raise ValueError("Invalid obseved bytes wrt Q and d")


def main():
    P, Q, d = gen_backdoor()
    # seed is some random value
    seed = randint(1, 2**30)
    dualec = DualEC(seed, P, Q)
    bits1 = dualec.genbits()
    bits2 = dualec.genbits()

    # We observe 34 bytes of output of the PRG
    # first: the 30 bytes from the first PRG computation
    observed1 = bits1
    # second: 4 bytes from the second PRG computation
    observed2 = (bits2 >> (26 * 8))
    print('Observed 34 bytes:\n({:x}, {:x})'.format(observed1, observed2))

    # We have to predict the other 26 bytes from the second PRG computation
    predicted = gen_prediction(observed1, observed2, P, Q, d)
    print('Predicted 26 bytes:\n{:x}'.format(predicted))

    # The actual other 26 bytes from the second PRG computation
    actual = bits2 & (2**(8 * 26) - 1)
    print('Actual 26 bytes:\n{:x}'.format(actual))

    print('Actual matches prediction:', actual == predicted)


if __name__ == '__main__':
    main()

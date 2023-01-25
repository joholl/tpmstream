from tpmstream.spec.structures.base_types import UINT32


class TestBaseTypes:
    def test_add(self):
        assert UINT32(2) + 3 == 5
        assert 2 + UINT32(3) == 5
        assert UINT32(2) + UINT32(3) == 5

    def test_sub(self):
        assert UINT32(5) - 3 == 2
        assert 5 - UINT32(3) == 2
        assert UINT32(5) - UINT32(3) == 2

    def test_mul(self):
        assert UINT32(2) * 3 == 6
        assert 2 * UINT32(3) == 6
        assert UINT32(2) * UINT32(3) == 6

    def test_truediv(self):
        assert UINT32(6) / 2 == 3
        assert 6 / UINT32(2) == 3
        assert UINT32(6) / UINT32(2) == 3

    def test_floordiv(self):
        assert UINT32(6) // 2 == 3
        assert 6 // UINT32(2) == 3
        assert UINT32(6) // UINT32(2) == 3

    def test_mod(self):
        assert UINT32(6) % 4 == 2
        assert 6 % UINT32(4) == 2
        assert UINT32(6) % UINT32(4) == 2

    def test_divmod(self):
        assert divmod(UINT32(6), 4) == (1, 2)
        assert divmod(6, UINT32(4)) == (1, 2)
        assert divmod(UINT32(6), UINT32(4)) == (1, 2)

    def test_pow(self):
        assert UINT32(3) ** 2 == 9
        assert 3 ** UINT32(2) == 9
        assert UINT32(3) ** UINT32(2) == 9

    def test_lshift(self):
        assert UINT32(0b0011) << 2 == 0b1100
        assert 0b0011 << UINT32(2) == 0b1100
        assert UINT32(0b0011) << UINT32(2) == 0b1100

    def test_rshift(self):
        assert UINT32(0b1100) >> 2 == 0b0011
        assert 0b1100 >> UINT32(2) == 0b0011
        assert UINT32(0b1100) >> UINT32(2) == 0b0011

    def test_and(self):
        assert UINT32(0b0011) & 0b0101 == 0b0001
        assert 0b0011 & UINT32(0b0101) == 0b0001
        assert UINT32(0b0011) & UINT32(0b0101) == 0b0001

    def test_xor(self):
        assert UINT32(0b0011) ^ 0b0101 == 0b0110
        assert 0b0011 ^ UINT32(0b0101) == 0b0110
        assert UINT32(0b0011) ^ UINT32(0b0101) == 0b0110

    def test_or(self):
        assert UINT32(0b0011) | 0b0101 == 0b0111
        assert 0b0011 | UINT32(0b0101) == 0b0111
        assert UINT32(0b0011) | UINT32(0b0101) == 0b0111

    def test_lt(self):
        assert UINT32(2) < 3
        assert not UINT32(2) < 2
        assert not UINT32(3) < 2

        assert 2 < UINT32(3)
        assert not 2 < UINT32(2)
        assert not 3 < UINT32(2)

        assert UINT32(2) < UINT32(3)
        assert not UINT32(2) < UINT32(2)
        assert not UINT32(3) < UINT32(2)

    def test_le(self):
        assert UINT32(2) <= 3
        assert UINT32(2) <= 2
        assert not UINT32(3) <= 2

        assert 2 <= UINT32(3)
        assert 2 <= UINT32(2)
        assert not 3 <= UINT32(2)

        assert UINT32(2) <= UINT32(3)
        assert UINT32(2) <= UINT32(2)
        assert not UINT32(3) <= UINT32(2)

    def test_eq(self):
        assert UINT32(5) == 5
        assert not UINT32(5) == 7

        assert 5 == UINT32(5)
        assert not 5 == UINT32(7)

        assert UINT32(5) == UINT32(5)
        assert not UINT32(5) == UINT32(7)

    def test_ne(self):
        assert not UINT32(5) != 5
        assert UINT32(5) != 7

        assert not 5 != UINT32(5)
        assert 5 != UINT32(7)

        assert not UINT32(5) != UINT32(5)
        assert UINT32(5) != UINT32(7)

    def test_gt(self):
        assert not UINT32(2) > 3
        assert not UINT32(2) > 2
        assert UINT32(3) > 2

        assert not 2 > UINT32(3)
        assert not 2 > UINT32(2)
        assert 3 > UINT32(2)

        assert not UINT32(2) > UINT32(3)
        assert not UINT32(2) > UINT32(2)
        assert UINT32(3) > UINT32(2)

    def test_ge(self):
        assert not UINT32(2) >= 3
        assert UINT32(2) >= 2
        assert UINT32(3) >= 2

        assert not 2 >= UINT32(3)
        assert 2 >= UINT32(2)
        assert 3 >= UINT32(2)

        assert not UINT32(2) >= UINT32(3)
        assert UINT32(2) >= UINT32(2)
        assert UINT32(3) >= UINT32(2)

    def test_hash(self):
        assert hash(UINT32(5)) == hash(5)
        assert hash(UINT32(5)) == hash(UINT32(5))

    def test_str(self):
        assert str(UINT32(5)) == "5"
        assert str(UINT32(-5)) == "-5"

    def test_repr(self):
        assert repr(UINT32(5)) == "UINT32(5)"
        assert repr(UINT32(-5)) == "UINT32(-5)"

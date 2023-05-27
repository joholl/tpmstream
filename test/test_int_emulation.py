from tpmstream.spec.structures.base_types import (
    BOOL,
    BYTE,
    INT8,
    INT16,
    INT32,
    INT64,
    UINT8,
    UINT16,
    UINT32,
    UINT64,
)


class TestArithmetic:
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


class TestValidValues:
    def test_valid_values_uint64(self):
        assert 0 in UINT64._valid_values
        assert 1 in UINT64._valid_values
        assert 0xFFFFFFFFFFFFFFFF in UINT64._valid_values

        assert -1 not in UINT64._valid_values
        assert 0x10000000000000000 not in UINT64._valid_values

    def test_valid_values_int64(self):
        assert -0x8000000000000000 in INT64._valid_values
        assert -1 in INT64._valid_values
        assert 0 in INT64._valid_values
        assert 1 in INT64._valid_values
        assert 0x7FFFFFFFFFFFFFFF in INT64._valid_values

        assert -0x8000000000000001 not in INT64._valid_values
        assert 0x8000000000000000 not in INT64._valid_values

    def test_valid_values_uint32(self):
        assert 0 in UINT32._valid_values
        assert 1 in UINT32._valid_values
        assert 0xFFFFFFFF in UINT32._valid_values

        assert -1 not in UINT32._valid_values
        assert 0x100000000 not in UINT32._valid_values

    def test_valid_values_int32(self):
        assert -0x80000000 in INT32._valid_values
        assert -1 in INT32._valid_values
        assert 0 in INT32._valid_values
        assert 1 in INT32._valid_values
        assert 0x7FFFFFFF in INT32._valid_values

        assert -0x80000001 not in INT32._valid_values
        assert 0x80000000 not in INT32._valid_values

    def test_valid_values_uint16(self):
        assert 0 in UINT16._valid_values
        assert 1 in UINT16._valid_values
        assert 0xFFFF in UINT16._valid_values

        assert -1 not in UINT16._valid_values
        assert 0x10000 not in UINT16._valid_values

    def test_valid_values_int16(self):
        assert -0x8000 in INT16._valid_values
        assert -1 in INT16._valid_values
        assert 0 in INT16._valid_values
        assert 1 in INT16._valid_values
        assert 0x7FFF in INT16._valid_values

        assert -0x8001 not in INT16._valid_values
        assert 0x8000 not in INT16._valid_values

    def test_valid_values_uint8(self):
        assert 0 in UINT8._valid_values
        assert 1 in UINT8._valid_values
        assert 0xFF in UINT8._valid_values

        assert -1 not in UINT8._valid_values
        assert 0x100 not in UINT8._valid_values

    def test_valid_values_int8(self):
        assert -0x80 in INT8._valid_values
        assert -1 in INT8._valid_values
        assert 0 in INT8._valid_values
        assert 1 in INT8._valid_values
        assert 0x7F in INT8._valid_values

        assert -0x81 not in INT8._valid_values
        assert 0x80 not in INT8._valid_values

    def test_valid_values_byte(self):
        assert 0 in UINT8._valid_values
        assert 1 in UINT8._valid_values
        assert 0xFF in UINT8._valid_values

        assert -1 not in UINT8._valid_values
        assert 0x100 not in UINT8._valid_values

    def test_valid_values_bool(self):
        assert 0 in BOOL._valid_values
        assert 1 in BOOL._valid_values

        assert -1 not in BOOL._valid_values
        assert 2 not in BOOL._valid_values


class TestToBytes:
    @staticmethod
    def as_signed(x, int_len):
        sign = 1 << (int_len - 1)
        sub = 1 << int_len
        if x & sign:
            x = x - sub
        return x

    def test_uint64(self):
        assert (
            UINT64(0x0000000000000000).to_bytes() == b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        assert (
            UINT64(0x0011223344556677).to_bytes() == b"\x00\x11\x22\x33\x44\x55\x66\x77"
        )
        assert (
            UINT64(0xFFEEDDCCBBAA9988).to_bytes() == b"\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
        )
        assert (
            UINT64(0xFFFFFFFFFFFFFFFF).to_bytes() == b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )

    def test_int64(self):
        assert (
            INT64(TestToBytes.as_signed(0x0000000000000000, 64)).to_bytes()
            == b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        assert (
            INT64(TestToBytes.as_signed(0x0011223344556677, 64)).to_bytes()
            == b"\x00\x11\x22\x33\x44\x55\x66\x77"
        )
        assert (
            INT64(TestToBytes.as_signed(0xFFEEDDCCBBAA9988, 64)).to_bytes()
            == b"\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
        )
        assert (
            INT64(TestToBytes.as_signed(0xFFFFFFFFFFFFFFFF, 64)).to_bytes()
            == b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )

    def test_uint32(self):
        assert UINT32(0x00000000).to_bytes() == b"\x00\x00\x00\x00"
        assert UINT32(0x00112233).to_bytes() == b"\x00\x11\x22\x33"
        assert UINT32(0xFFEEDDCC).to_bytes() == b"\xff\xee\xdd\xcc"
        assert UINT32(0xFFFFFFFF).to_bytes() == b"\xff\xff\xff\xff"

    def test_int32(self):
        assert (
            INT32(TestToBytes.as_signed(0x00000000, 32)).to_bytes()
            == b"\x00\x00\x00\x00"
        )
        assert (
            INT32(TestToBytes.as_signed(0x00112233, 32)).to_bytes()
            == b"\x00\x11\x22\x33"
        )
        assert (
            INT32(TestToBytes.as_signed(0xFFEEDDCC, 32)).to_bytes()
            == b"\xff\xee\xdd\xcc"
        )
        assert (
            INT32(TestToBytes.as_signed(0xFFFFFFFF, 32)).to_bytes()
            == b"\xff\xff\xff\xff"
        )

    def test_uint16(self):
        assert UINT16(0x0000).to_bytes() == b"\x00\x00"
        assert UINT16(0x0011).to_bytes() == b"\x00\x11"
        assert UINT16(0xFFEE).to_bytes() == b"\xff\xee"
        assert UINT16(0xFFFF).to_bytes() == b"\xff\xff"

    def test_int16(self):
        assert INT16(TestToBytes.as_signed(0x0000, 16)).to_bytes() == b"\x00\x00"
        assert INT16(TestToBytes.as_signed(0x0011, 16)).to_bytes() == b"\x00\x11"
        assert INT16(TestToBytes.as_signed(0xFFEE, 16)).to_bytes() == b"\xff\xee"
        assert INT16(TestToBytes.as_signed(0xFFFF, 16)).to_bytes() == b"\xff\xff"

    def test_uint8(self):
        assert UINT8(0x00).to_bytes() == b"\x00"
        assert UINT8(0x11).to_bytes() == b"\x11"
        assert UINT8(0xEE).to_bytes() == b"\xee"
        assert UINT8(0xFF).to_bytes() == b"\xff"

    def test_int8(self):
        assert INT8(TestToBytes.as_signed(0x00, 8)).to_bytes() == b"\x00"
        assert INT8(TestToBytes.as_signed(0x11, 8)).to_bytes() == b"\x11"
        assert INT8(TestToBytes.as_signed(0xEE, 8)).to_bytes() == b"\xee"
        assert INT8(TestToBytes.as_signed(0xFF, 8)).to_bytes() == b"\xff"

    def test_byte(self):
        assert BYTE(0x00).to_bytes() == b"\x00"
        assert BYTE(0x11).to_bytes() == b"\x11"
        assert BYTE(0xEE).to_bytes() == b"\xee"
        assert BYTE(0xFF).to_bytes() == b"\xff"

    def test_bool(self):
        assert BOOL(0x00).to_bytes() == b"\x00"
        assert BOOL(0x01).to_bytes() == b"\x01"

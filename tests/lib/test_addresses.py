# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

import pytest

from lib.coins import Groestlcoin
from lib.hash import Base58

addresses = [
    (Groestlcoin, "FY7vmDL7FZGACwqVNx5p4fVaGghojWM5AF",
    "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
]


@pytest.fixture(params=addresses)
def address(request):
    return request.param


def test_address_to_hashX(address):
    coin, addr, _, hashX = address
    assert coin.address_to_hashX(addr).hex() == hashX


def test_address_from_hash160(address):
    coin, addr, hash, _ = address

    raw = coin.DECODE_CHECK(addr)
    verlen = len(raw) - 20
    assert verlen > 0
    verbyte, hash_bytes = raw[:verlen], raw[verlen:]
    if coin.P2PKH_VERBYTE == verbyte:
        assert coin.P2PKH_address_from_hash160(bytes.fromhex(hash)) == addr
    elif verbyte in coin.P2SH_VERBYTES:
        assert coin.P2SH_address_from_hash160(bytes.fromhex(hash)) == addr
    else:
        raise Exception("Unknown version byte")

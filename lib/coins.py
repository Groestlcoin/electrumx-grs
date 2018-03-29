# Copyright (c) 2016-2017, Neil Booth
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

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

from collections import namedtuple
import re
import struct
from decimal import Decimal
from hashlib import sha256

import lib.util as util
from lib.hash import Base58, hash160, double_sha256, hash_to_str, groestlHash
from lib.script import ScriptPubKey, OpCodes
import lib.tx as lib_tx
from server.block_processor import BlockProcessor
import server.daemon as daemon
from server.session import ElectrumX, DashElectrumX


Block = namedtuple("Block", "raw header transactions")
OP_RETURN = OpCodes.OP_RETURN


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin(object):
    '''Base class of coin hierarchy.'''

    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\[[0-9a-fA-F:]+\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    CHUNK_SIZE = 2016
    HASHX_LEN = 11
    BASIC_HEADER_SIZE = 80
    STATIC_BLOCK_HEADERS = True
    SESSIONCLS = ElectrumX
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = BlockProcessor
    XPUB_VERBYTES = bytes('????', 'utf-8')
    XPRV_VERBYTES = bytes('????', 'utf-8')
    ENCODE_CHECK = Base58.encode_check
    DECODE_CHECK = Base58.decode_check
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        # Only Groestlcoin can be used with electrumx-grs.
        if name.lower() != 'groestlcoin':
            raise CoinError('Only Groestlcoin can be used with electrumx-grs.')
        req_attrs = ['TX_COUNT', 'TX_COUNT_HEIGHT', 'TX_PER_BLOCK',
                     'IRC_CHANNEL']
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower() and
                    coin.NET.lower() == net.lower()):
                coin_req_attrs = req_attrs.copy()
                missing = [attr for attr in coin_req_attrs
                           if not hasattr(coin, attr)]
                if missing:
                    raise CoinError('coin {} missing {} attributes'
                                    .format(name, missing))
                return coin
        raise CoinError('unknown coin {} and network {} combination'
                        .format(name, net))

    @classmethod
    def sanitize_url(cls, url):
        # Remove surrounding ws and trailing /s
        url = url.strip().rstrip('/')
        match = cls.RPC_URL_REGEX.match(url)
        if not match:
            raise CoinError('invalid daemon URL: "{}"'.format(url))
        if match.groups()[1] is None:
            url += ':{:d}'.format(cls.RPC_PORT)
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        return url + '/'

    @classmethod
    def daemon_urls(cls, urls):
        return [cls.sanitize_url(url) for url in urls.split(',')]

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))

        return header + bytes(1)

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script, or None if the script is provably
        unspendable so the output can be dropped.
        '''
        if script and script[0] == OP_RETURN:
            return None
        return sha256(script).digest()[:cls.HASHX_LEN]

    @util.cachedproperty
    def address_handlers(cls):
        return ScriptPubKey.PayToHandlers(
            address=cls.P2PKH_address_from_hash160,
            script_hash=cls.P2SH_address_from_hash160,
            pubkey=cls.P2PKH_address_from_pubkey,
            unspendable=lambda: None,
            strange=lambda script: None,
        )

    @classmethod
    def address_from_script(cls, script):
        '''Given a pk_script, return the adddress it pays to, or None.'''
        return ScriptPubKey.pay_to(cls.address_handlers, script)

    @staticmethod
    def lookup_xverbytes(verbytes):
        '''Return a (is_xpub, coin_class) pair given xpub/xprv verbytes.'''
        # Order means BTC testnet will override NMC testnet
        for coin in util.subclasses(Coin):
            if verbytes == coin.XPUB_VERBYTES:
                return True, coin
            if verbytes == coin.XPRV_VERBYTES:
                return False, coin
        raise CoinError('version bytes unrecognised')

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

    @classmethod
    def P2PKH_address_from_hash160(cls, hash160):
        '''Return a P2PKH address given a public key.'''
        assert len(hash160) == 20
        return cls.ENCODE_CHECK(cls.P2PKH_VERBYTE + hash160)

    @classmethod
    def P2PKH_address_from_pubkey(cls, pubkey):
        '''Return a coin address given a public key.'''
        return cls.P2PKH_address_from_hash160(hash160(pubkey))

    @classmethod
    def P2SH_address_from_hash160(cls, hash160):
        '''Return a coin address given a hash160.'''
        assert len(hash160) == 20
        return cls.ENCODE_CHECK(cls.P2SH_VERBYTES[0] + hash160)

    @classmethod
    def multisig_address(cls, m, pubkeys):
        '''Return the P2SH address for an M of N multisig transaction.

        Pass the N pubkeys of which M are needed to sign it.  If
        generating an address for a wallet, it is the caller's
        responsibility to sort them to ensure order does not matter
        for, e.g., wallet recovery.
        '''
        script = cls.pay_to_multisig_script(m, pubkeys)
        return cls.P2SH_address_from_hash160(hash160(script))

    @classmethod
    def pay_to_multisig_script(cls, m, pubkeys):
        '''Return a P2SH script for an M of N multisig transaction.'''
        return ScriptPubKey.multisig_script(m, pubkeys)

    @classmethod
    def pay_to_pubkey_script(cls, pubkey):
        '''Return a pubkey script that pays to a pubkey.

        Pass the raw pubkey bytes (length 33 or 65).
        '''
        return ScriptPubKey.P2PK_script(pubkey)

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a pubkey hash.

        Pass the address (either P2PKH or P2SH) in base58 form.
        '''
        raw = cls.DECODE_CHECK(address)

        # Require version byte(s) plus hash160.
        verbyte = -1
        verlen = len(raw) - 20
        if verlen > 0:
            verbyte, hash_bytes = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return ScriptPubKey.P2PKH_script(hash_bytes)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash_bytes)

        raise CoinError('invalid address: {}'.format(address))

    @classmethod
    def privkey_WIF(cls, privkey_bytes, compressed):
        '''Return the private key encoded in Wallet Import Format.'''
        payload = bytearray(cls.WIF_BYTE) + privkey_bytes
        if compressed:
            payload.append(0x01)
        return cls.ENCODE_CHECK(payload)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        assert cls.STATIC_BLOCK_HEADERS
        return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        return cls.static_header_offset(height + 1) \
               - cls.static_header_offset(height)

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        return block[:cls.static_header_len(height)]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        header = cls.block_header(raw_block, height)
        txs = cls.DESERIALIZER(raw_block, start=len(header)).read_tx_block()
        return Block(raw_block, header, txs)

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BTC is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN

    @classmethod
    def electrum_header(cls, header, height):
        version, = struct.unpack('<I', header[:4])
        timestamp, bits, nonce = struct.unpack('<III', header[68:80])

        return {
            'block_height': height,
            'version': version,
            'prev_block_hash': hash_to_str(header[4:36]),
            'merkle_root': hash_to_str(header[36:68]),
            'timestamp': timestamp,
            'bits': bits,
            'nonce': nonce,
        }


class AuxPowMixin(object):
    STATIC_BLOCK_HEADERS = False
    DESERIALIZER = lib_tx.DeserializerAuxPow

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])

    @classmethod
    def block_header(cls, block, height):
        '''Return the AuxPow block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(height, cls.BASIC_HEADER_SIZE)


class Groestlcoin(Coin):
    NAME = "Groestlcoin"
    SHORTNAME = "GRS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    GENESIS_HASH = ('00000ac5927c594d49cc0bdb81759d0d'
                    'a8297eb614683d3acb62f0703b639023')
    DESERIALIZER = lib_tx.DeserializerSegWit
    P2PKH_VERBYTE = bytes.fromhex("24")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")

    TX_COUNT = 115900
    TX_COUNT_HEIGHT = 1601528
    TX_PER_BLOCK = 5

    IRC_PREFIX = "E-grs_"
    IRC_CHANNEL = "#Groestlcoin"
    RPC_PORT = 1441
    PEERS = [
        'electrum1.groestlcoin.org s t',
        'electrum2.groestlcoin.org s t',
        'electrum3.groestlcoin.org s t',
        'electrum4.groestlcoin.org s t',
        'electrum5.groestlcoin.org s t',
        'electrum6.groestlcoin.org s t',
        'electrum7.groestlcoin.org s t',
        'electrum8.groestlcoin.org s t',
        'electrum9.groestlcoin.org s t',
        'electrum10.groestlcoin.org s t',
        'electrum11.groestlcoin.org s t',
        'electrum12.groestlcoin.org s t',
        'electrum13.groestlcoin.org s t',
        'electrum14.groestlcoin.org s t',
        'electrum15.groestlcoin.org s t',
        'electrum16.groestlcoin.org s t',
        'electrum17.groestlcoin.org s t',
        'electrum18.groestlcoin.org s t',
        'electrum19.groestlcoin.org s t',
        'electrum20.groestlcoin.org s t',
        'electrum21.groestlcoin.org s t',
        'electrum22.groestlcoin.org s t',
        'electrum23.groestlcoin.org s t',
        'electrum24.groestlcoin.org s t',
        'electrum25.groestlcoin.org s t',
        'electrum26.groestlcoin.org s t',
        'electrum27.groestlcoin.org s t',
        'electrum28.groestlcoin.org s t',
        'electrum29.groestlcoin.org s t',
        'electrum30.groestlcoin.org s t',
        'electrum31.groestlcoin.org s t',
        'electrum32.groestlcoin.org s t',
        'electrum33.groestlcoin.org s t',
        'electrum34.groestlcoin.org s t',
        'electrum35.groestlcoin.org s t',
        'electrum36.groestlcoin.org s t',
        'electrum37.groestlcoin.org s t',
        'electrum38.groestlcoin.org s t',
        'electrum39.groestlcoin.org s t',
        'electrum40.groestlcoin.org s t',
        '6brsrbiinpc32tfc.onion t',
        'xkj42efxrcy6vbfw.onion t',
        'j2pokkxrnqifawlo.onion t',
        'fxqag2xgbttgpn5t.onion t',
        'wbu6iwai7g5vsmqf.onion t',
        'ozarkd36gllcq64p.onion t',
        'lgafnxxckcohp3lb.onion t',
        'daxevrnxtrjtatnq.onion t',
        '54fufvlyfsv6mu27.onion t',
        'oopkp4mazgysotus.onion t',
        'imfxdu2iaxphpzoj.onion t',
        'msu62n2wehlyvu73.onion t',
        '4g54umgydy2efvkp.onion t',
        'nxb5shpaqcppuaac.onion t',
        'liciqskhe3kb56sx.onion t',
        '6urwohx677tqyx4d.onion t',
        'jmkqrcrthxzgijzc.onion t',
        'o2i7q65crpvgkyhp.onion t',
        'sakl2ebpspx4yqux.onion t',
        'kahwte3yfwedilib.onion t',
        '4jnj4nztibl6nzr7.onion t',
        '7bh7oexd6sgaa2ui.onion t',
        '6txnygqn2lo3pas7.onion t',
        'vhaltx6l3qz7m6gm.onion t',
        'pcorvh3z6l4qsfvh.onion t',
        '4vncucq2hxqgobn4.onion t',
        'ezwaifwooob3xitg.onion t',
        'uqxfaectrpqqvogm.onion t',
        'tewjvvb2acejbpwu.onion t',
        'bmbrjepkos5brm3m.onion t',
        'evkxwqlvatx2bbuk.onion t',
        'ekjgl6n6jhcqfq2x.onion t',
        '5seia6dn4dphcw4n.onion t',
        'qqgqih4nuhvsprqa.onion t',
        'ygovc7jlb6itiis4.onion t',
        'f33ys4h3e4nbdrdm.onion t',
        'csg7djvlqujxn4qt.onion t',
        'yw7dotigvofzqmql.onion t',
        'aal7howc56u3j5bg.onion t',
        'gnuvqomyhedouwqw.onion t',
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return groestlHash(header)

class GroestlcoinTestnet(Groestlcoin):
    SHORTNAME = "TGRS"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000000ffbb50fc9898cdd36ec163e6ba'
                    '23230164c0052a28876255b7dcf2cd36')

    IRC_PREFIX = "E-tgrs_"
    RPC_PORT = 17766
    PEERS = [
        'electrum-test1.groestlcoin.org s t',
        'electrum-test2.groestlcoin.org s t',
        '7frvhgofuf522b5i.onion t',
        'aocojvqcybdoxekv.onion t',
    ]


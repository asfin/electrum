import io
from copy import deepcopy
from typing import Tuple, List

from .bitcoin import varint_to_int, xpub_from_pubkey, convert_raw_uint32_to_bip32_path
from .keystore import xpubkey_to_pubkey
from .transaction import Transaction, SerializationError
from .util import bh2u

# BIP174 constants - https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
PSBT_GLOBAL_UNSIGNED_TX = b'\x00'
PSBT_IN_NON_WITNESS_UTXO = b'\x00'
PSBT_IN_WITNESS_UTXO = b'\x01'
PSBT_IN_PARTIAL_SIG = b'\x02'
PSBT_IN_SIGHASH_TYPE = b'\x03'
PSBT_IN_REDEEM_SCRIPT = b'\x04'
PSBT_IN_WITNESS_SCRIPT = b'\x05'
PSBT_IN_BIP32_DERIVATION = b'\x06'
PSBT_IN_FINAL_SCRIPTSIG = b'\x07'
PSBT_IN_FINAL_SCRIPTWITNESS = b'\x08'
PSBT_OUT_REDEEM_SCRIPT = b'\x00'
PSBT_OUT_WITNESS_SCRIPT = b'\x01'
PSBT_OUT_BIP32_DERIVATION = b'\x02'
PSBT_TXN_HEADER_MAGIC = b'psbt\xff'


def _validate_unsigned_tx(key: bytes, value: bytes):
    if key != b'':
        raise SerializationError('Unexpected key')
    tx = Transaction(bh2u(value))
    tx.deserialize(True)
    s, r = tx.signature_count()
    if s > 0:
        raise SerializationError('Found signed inputs in unsigned tx')
    return None, bh2u(value)


def _validate_partial_sig(key: bytes, value: bytes):
    return bh2u(key), value


def _validate_bip32(key: str, value: bytes):
    if len(key) != 66:
        raise SerializationError('Invalid key value')
    fpr, raw_path = value[:4], value[4:]
    bip32_path = convert_raw_uint32_to_bip32_path(raw_path)

    res = {
        'master_fingerprint': bh2u(fpr),
        'bip32_path': bip32_path,
    }
    return res


_keytypes = {
    'global': {  # (name, has_key)
        PSBT_GLOBAL_UNSIGNED_TX: ('unsigned_tx', False),
    },
    'inputs': {
        PSBT_IN_NON_WITNESS_UTXO: ('non_witness_utxo', False),
        PSBT_IN_WITNESS_UTXO: ('witness_utxo', False),
        PSBT_IN_PARTIAL_SIG: ('partial_sig', True),
        PSBT_IN_SIGHASH_TYPE: ('sighash_type', False),
        PSBT_IN_REDEEM_SCRIPT: ('redeem_script', False),
        PSBT_IN_WITNESS_SCRIPT: ('witness_script', False),
        PSBT_IN_BIP32_DERIVATION: ('bip32_derivation', True),
        PSBT_IN_FINAL_SCRIPTSIG: ('final_scriptsig', False),
        PSBT_IN_FINAL_SCRIPTWITNESS: ('final_scriptwitness', False),
    },
    'outputs': {
        PSBT_OUT_REDEEM_SCRIPT: ('redeem_script', False),
        PSBT_OUT_WITNESS_SCRIPT: ('witness_script', False),
        PSBT_OUT_BIP32_DERIVATION: ('bip32_derivation', True),
    }
}


def _parse_stream(stream: io.BytesIO):
    out = []
    while 1:
        _len, _ = varint_to_int(stream)
        if _len is None:
            # EOF
            raise SerializationError('Invalid tx format: missing sections')
        if _len == 0:
            break

        full_key = stream.read(_len)
        key_type, key = full_key[:1], full_key[1:]
        print('keylen', _len, 'type', bh2u(key_type), 'key', bh2u(key))

        _len, _ = varint_to_int(stream)
        if _len is None:
            raise SerializationError('Invalid tx format: missing sections')
        value = stream.read(_len)
        print('vallen', _len, 'value', bh2u(value))

        out.append((key_type, key, value))
    return out


def _construct_args(arr: list, keymap: dict) -> dict:
    d = {}
    for kt, k, v in arr:
        kname, has_subkeys = keymap.get(kt, (kt, True))
        if has_subkeys:
            if d.get(kname) is None:
                d[kname] = {}
            if d[kname].get(bh2u(k)) is None:
                d[kname][bh2u(k)] = v
            else:
                raise SerializationError('Duplicate key')

        else:
            if d.get(kname) is None:
                d[kname] = v
            else:
                raise SerializationError('Duplicate key')
    return d


class PSBTGlobal:
    num_inputs = None
    num_outputs = None
    unsigned_tx = None

    def __init__(self, unsigned_tx, **kw):
        if isinstance(unsigned_tx, bytes):
            unsigned_tx = bh2u(unsigned_tx)
        self.unsigned_tx = Transaction(unsigned_tx)
        self.unsigned_tx.deserialize()
        self.num_inputs = len(self.unsigned_tx.inputs())
        self.num_outputs = len(self.unsigned_tx.outputs())

    @staticmethod
    def deserialize(stream: io.BytesIO):
        arr = _parse_stream(stream)
        keymap = _keytypes['global']
        d = _construct_args(arr, keymap)

        try:
            section = PSBTGlobal(**d)
        except TypeError:
            raise SerializationError('Invalid tx format: missing sections')
        return section


class PSBTInput:
    non_witness_utxo = None
    witness_utxo = None
    partial_sig = None
    sighash_type = None
    redeem_script = None
    witness_script = None
    bip32_derivation = None
    final_scriptsig = None
    final_scriptwitness = None
    unknown = None  # TODO: handle unknown keys

    def __init__(self, **kw):
        kw = deepcopy(kw)
        self.non_witness_utxo = kw.pop('non_witness_utxo', None)
        self.witness_utxo = kw.pop('witness_utxo', None)
        self.partial_sig = kw.pop('partial_sig', None)
        self.sighash_type = kw.pop('sighash_type', None)
        self.redeem_script = kw.pop('redeem_script', None)
        self.witness_script = kw.pop('witness_script', None)
        self.bip32_derivation = kw.pop('bip32_derivation', None)
        self.final_scriptsig = kw.pop('final_scriptsig', None)
        self.final_scriptwitness = kw.pop('final_scriptwitness', None)

        if self.non_witness_utxo:
            if isinstance(self.non_witness_utxo, bytes):
                self.non_witness_utxo = bh2u(self.non_witness_utxo)
            if isinstance(self.non_witness_utxo, str):
                self.non_witness_utxo = Transaction(self.non_witness_utxo)

        if self.bip32_derivation:
            for k, v in self.bip32_derivation.items():
                if isinstance(v, bytes):
                    v = _validate_bip32(k, v)
                    self.bip32_derivation[k] = v
                if isinstance(v, dict):
                    assert v.get('master_fingerprint')
                    assert v.get('bip32_path')
        if self.sighash_type:
            pass

    @staticmethod
    def deserialize(stream: io.BytesIO):
        arr = _parse_stream(stream)
        keymap = _keytypes['inputs']
        d = _construct_args(arr, keymap)

        return PSBTInput(**d)


class PSBTOutput:
    redeem_script = None
    witness_script = None
    bip32_derivation = None

    def __init__(self, **kw):
        kw = deepcopy(kw)
        self.redeem_script = kw.pop('redeem_script', None)
        self.witness_script = kw.pop('witness_script', None)
        self.bip32_derivation = kw.pop('bip32_derivation', None)

        if self.bip32_derivation:
            for k, v in self.bip32_derivation.items():
                if isinstance(v, bytes):
                    v = _validate_bip32(k, v)
                    self.bip32_derivation[k] = v
                if isinstance(v, dict):
                    assert v.get('master_fingerprint')
                    assert v.get('bip32_path')

    @staticmethod
    def deserialize(stream: io.BytesIO):
        arr = _parse_stream(stream)
        keymap = _keytypes['outputs']
        d = _construct_args(arr, keymap)

        return PSBTOutput(**d)


def psbt_parser(raw_bytes: bytes) -> Tuple[PSBTGlobal, List[PSBTInput], List[PSBTOutput]]:
    stream = io.BytesIO(raw_bytes)

    hdr = stream.read(5)
    if hdr != PSBT_TXN_HEADER_MAGIC:
        raise SerializationError('Bad PSBT header')

    global_section = PSBTGlobal.deserialize(stream)
    input_sections = []
    output_sections = []
    for _ in range(global_section.num_inputs):
        input_sections.append(PSBTInput.deserialize(stream))
    for _ in range(global_section.num_outputs):
        output_sections.append(PSBTOutput.deserialize(stream))

    if global_section.num_outputs != len(output_sections):
        raise SerializationError('Invalid tx format: missing sections')

    return global_section, input_sections, output_sections


def psbt_serializer(tx: Transaction) -> bytes:
    pass

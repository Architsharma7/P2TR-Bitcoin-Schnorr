from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Dict
import hashlib
from taproot_common import *

# -------------------------
# Taproot tweak helpers
# -------------------------

def tap_tweak(internal_x_hex: str, merkle_root_hex: str = "") -> int:
    t_hex = tagged_hash("TapTweak", internal_x_hex + merkle_root_hex)
    return h2i(t_hex) % N

def tweak_pubkey(internal_x_hex: str, merkle_root_hex: str = "") -> Dict[str, str]:
    Ppt = lift_x(internal_x_hex)
    t = tap_tweak(internal_x_hex, merkle_root_hex)
    tG = mul(t, G)
    Qpt = add(Ppt, tG)
    return {"x_hex": i2h(Qpt["x"]), "y": Qpt["y"]}

def tweak_seckey(seckey_hex: str, internal_x_hex: str, merkle_root_hex: str = "") -> str:
    d0 = h2i(seckey_hex) % N
    if not (1 <= d0 < N):
        raise ValueError("seckey out of range")
    Ppt = mul(d0, G)
    d = (N - d0) if (Ppt["y"] % 2 != 0) else d0
    t = tap_tweak(internal_x_hex, merkle_root_hex)
    dprime = (d + t) % N
    if dprime == 0:
        raise ValueError("invalid tweak (d' == 0)")
    return i2h(dprime)

def p2tr_scriptpubkey(internal_x_hex: str, merkle_root_hex: str = "") -> str:
    xq = tweak_pubkey(internal_x_hex, merkle_root_hex)["x_hex"]
    return "51" + "20" + xq

# -------------------------
# BIP341 SIGHASH
# -------------------------
@dataclass
class TxIn:
    txid: str               # big-endian hex
    vout: int
    amount_sats: int
    prevout_scriptpubkey: str  # hex 
    sequence: int = 0xFFFFFFFF

@dataclass
class TxOut:
    amount_sats: int
    scriptpubkey: str       # hex 


def _hash_inputs_vectors(inputs: List[TxIn]) -> Dict[str, str]:
    # prevouts = concat(LE(txid) || LE(vout))
    prevouts_hex  = ''.join([reversebytes(i.txid) + le(i.vout, 4) for i in inputs])

    # amounts = concat(LE(amount))
    amounts_hex   = ''.join([le(i.amount_sats, 8) for i in inputs])

    # sequences = concat(LE(sequence))
    sequences_hex = ''.join([le(i.sequence, 4) for i in inputs])

    # scriptpubkeys = concat(CompactSize(len) || script)
    spks_hex      = ''.join([serialize_script(i.prevout_scriptpubkey) for i in inputs])

    return {
        "sha_prevouts": hashlib.sha256(bytes.fromhex(prevouts_hex)).hexdigest(),
        "sha_amounts": hashlib.sha256(bytes.fromhex(amounts_hex)).hexdigest(),
        "sha_sequences": hashlib.sha256(bytes.fromhex(sequences_hex)).hexdigest(),
        "sha_spks": hashlib.sha256(bytes.fromhex(spks_hex)).hexdigest(),
    }


# === Byte helpers ===

def le(n: int, size: int) -> str:
    return n.to_bytes(size, "little").hex()

def dsha256(hexstr: str) -> bytes:
    b = bytes.fromhex(hexstr)
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def txid_from_nonwitness(nonwit_hex: str) -> str:
    """RPC-style txid (big-endian hex): double-SHA256 of non-witness serialization, then reverse bytes."""
    return dsha256(nonwit_hex)[::-1].hex()

def wtxid_from_witness(full_hex: str) -> str:
    """wtxid (big-endian hex): double-SHA256 of full segwit serialization, then reverse bytes."""
    return dsha256(full_hex)[::-1].hex()

# === Serializers ===
def _ser_input(i: TxIn) -> str:
    # outpoint
    outpoint = reversebytes(i.txid) + le(i.vout, 4)
    # empty scriptSig
    scriptsig_len = "00"
    # sequence
    seq = le(i.sequence, 4)
    return outpoint + scriptsig_len + seq

def _ser_output(o: TxOut) -> str:
    return le(o.amount_sats, 8) + serialize_script(o.scriptpubkey)

def _ser_witness_stacks(witnesses: list[list[str]]) -> str:
    """
    witnesses: list (per input) of stacks; each stack is list of hex items (no varint).
    For Taproot key-path each input has exactly one item: <64-byte sig || 0x01>.
    """
    allw = ""
    for stack in witnesses:
        allw += compact_size(len(stack))
        for item in stack:
            allw += compact_size(len(item) // 2) + item
    return allw

def assemble_segwit_tx(version: int,
                       inputs: list[TxIn],
                       outputs: list[TxOut],
                       witnesses: list[list[str]],
                       locktime: int) -> dict[str, str]:
    """
    Build raw segwit tx hex + txid + wtxid.
    - witnesses must have one entry per input (list of stack items per input, as hex).
    - For Taproot key-path, a single item per input: sig||01.
    """
    if len(inputs) != len(witnesses):
        raise ValueError("witnesses length must match inputs length")

    ver = le(version, 4)                  # 4-byte LE
    marker_flag = "0001"                  # segwit marker+flag
    vin_count = compact_size(len(inputs))
    vouts_count = compact_size(len(outputs))

    vin_hex = "".join(_ser_input(i) for i in inputs)
    vouts_hex = "".join(_ser_output(o) for o in outputs)
    wit_hex = _ser_witness_stacks(witnesses)
    lock = le(locktime, 4)

    # Full segwit serialization (BIP144):
    full_hex = ver + marker_flag + vin_count + vin_hex + vouts_count + vouts_hex + wit_hex + lock

    # Non-witness serialization (for txid):
    nonwit_hex = ver + vin_count + vin_hex + vouts_count + vouts_hex + lock

    return {
        "raw": full_hex,
        "txid": txid_from_nonwitness(nonwit_hex),
        "wtxid": wtxid_from_witness(full_hex),
        "nonwitness_hex": nonwit_hex
    }

def sign_and_assemble_keypath_all(version: int,
                                  locktime: int,
                                  inputs: list[TxIn],
                                  outputs: list[TxOut],
                                  input_index: int,
                                  internal_x_hex: str,
                                  seckey_hex: str,
                                  merkle_root_hex: str = "",
                                  aux_rand_hex: str = "00"*32) -> dict[str, str]:
    """
    Signs the specified input (key-path, SIGHASH_ALL) and assembles a broadcastable tx.
    Assumes **all inputs are Taproot key-path** and need exactly one witness item each.
    For multi-input, call sign_input_keypath_all per input and collect witnesses in order.
    """
    # produce signature for the target input
    sig_res = sign_input_keypath_all(
        version, locktime, inputs, outputs, input_index,
        internal_x_hex, seckey_hex, merkle_root_hex, aux_rand_hex
    )
    # witness items per input (default empty for others)
    witnesses = [[""] for _ in inputs]  # placeholder shape
    # fill each input with a stack; for non-targets, user should set signatures too.
    witnesses = [[] for _ in inputs]
    for idx in range(len(inputs)):
        if idx == input_index:
            witnesses[idx] = [sig_res["sig"] + sig_res["hash_type_byte"]]
        else:
            # If other inputs exist, you must sign them too.
            witnesses[idx] = []  # empty → invalid until signed

    tx = assemble_segwit_tx(version, inputs, outputs, witnesses, locktime)
    tx.update(sig_res)
    return tx



def _hash_outputs_vector(outputs: List[TxOut]) -> str:
    out_hex = ''
    for o in outputs:
        out_hex += le(o.amount_sats, 8) + serialize_script(o.scriptpubkey)
    return hashlib.sha256(bytes.fromhex(out_hex)).hexdigest()



def spend_type_byte(ext_flag: int, annex_present: int) -> str:
    return f"{((ext_flag << 1) | (annex_present & 1)) & 0xFF:02x}"


def build_sigmsg_keypath_all(version: int, locktime: int, inputs: List[TxIn], outputs: List[TxOut], input_index: int = 0, anyone_can_pay: bool = False, annex_hex: Optional[str] = None) -> str:
    htype_byte = "01"  # SIGHASH_ALL
    v_hex = f"{version:08x}"
    l_hex = f"{locktime:08x}"

    sigmsg = htype_byte + reversebytes(v_hex) + reversebytes(l_hex)

    if not anyone_can_pay:
        hv = _hash_inputs_vectors(inputs)
        sigmsg += hv["sha_prevouts"] + hv["sha_amounts"] + hv["sha_spks"] + hv["sha_sequences"]
    # outputs (ALL)
    sigmsg += _hash_outputs_vector(outputs)

    # spend type: key-path (0), annex flag
    annex_present = 1 if (annex_hex and len(annex_hex) > 0) else 0
    sigmsg += spend_type_byte(0, annex_present)

    if not anyone_can_pay:
        sigmsg += f"{input_index:08x}"
    else:
        # include this input fully
        i = inputs[input_index]
        sigmsg += reversebytes(i.txid)
        sigmsg += f"{i.vout:08x}"
        sigmsg += f"{i.amount_sats:016x}"
        sigmsg += serialize_script(i.prevout_scriptpubkey)
        sigmsg += f"{i.sequence:08x}"

    if annex_present:
        sigmsg += hashlib.sha256(bytes.fromhex(annex_hex)).hexdigest()

    return sigmsg


def taproot_sighash(sigmsg_hex: str, epoch_byte: str = "00") -> str:
    return tagged_hash("TapSighash", epoch_byte + sigmsg_hex)

# -------------------------
# BIP340 signing (key-path)
# -------------------------

def schnorr_sign_taproot(message_hex: str, tweaked_priv_hex: str, pub_x_hex: str, aux_rand_hex: Optional[str] = None) -> str:
    if aux_rand_hex is None:
        aux_rand_hex = "00" * 32
    d0 = h2i(tweaked_priv_hex) % N
    if d0 <= 0 or d0 >= N:
        raise ValueError("private key out of range")

    Ppt = mul(d0, G)
    d = (N - d0) if (Ppt["y"] % 2 != 0) else d0

    aux_hash = tagged_hash("BIP0340/aux", aux_rand_hex)
    t = d ^ h2i(aux_hash)
    nonce_input = i2h(t) + pub_x_hex + message_hex
    k0 = h2i(tagged_hash("BIP0340/nonce", nonce_input)) % N
    if k0 == 0:
        raise ValueError("k0 == 0")

    R = mul(k0, G)
    k = (N - k0) if (R["y"] % 2 != 0) else k0
    r_x_hex = i2h(R["x"])
    e = h2i(tagged_hash("BIP0340/challenge", r_x_hex + pub_x_hex + message_hex)) % N
    s = (k + e * d) % N
    return r_x_hex + i2h(s)


def sign_input_keypath_all(version: int, locktime: int, inputs: List[TxIn], outputs: List[TxOut], input_index: int, internal_x_hex: str, seckey_hex: str, merkle_root_hex: str = "", aux_rand_hex: Optional[str] = None) -> Dict[str, str]:
    # Build preimage and sighash
    sigmsg = build_sigmsg_keypath_all(version, locktime, inputs, outputs, input_index)
    sighash = taproot_sighash(sigmsg)

    # Compute tweaked secret and tweaked pub x
    dprime_hex = tweak_seckey(seckey_hex, internal_x_hex, merkle_root_hex)
    xq_hex = tweak_pubkey(internal_x_hex, merkle_root_hex)["x_hex"]

    # Schnorr sign
    sig64 = schnorr_sign_taproot(sighash, dprime_hex, xq_hex, aux_rand_hex)
    return {"sig": sig64, "sighash": sighash, "hash_type_byte": "01"}


def witness_stack_item_sig(sig_hex: str, hash_type_byte: str = "01") -> str:
    """Return the single witness stack item for Taproot key-path: <64-byte sig || sighash byte> with its varint length.
    This returns just the item payload; when assembling the full witness, prefix with stack count and other items if any.
    """
    b = sig_hex + hash_type_byte
    return b
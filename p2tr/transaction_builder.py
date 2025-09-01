from bech32 import bech32_decode, convertbits
from taproot_key_path_spend import *

def spk_from_segwit_addr(addr: str) -> str:
    hrp, data = bech32_decode(addr)        
    if hrp is None:
        raise ValueError("bad bech32/bech32m address")
    witver = data[0]
    prog = bytes(convertbits(data[1:], 5, 8, False))  
    if witver == 0:
        if len(prog) not in (20, 32):
            raise ValueError("v0 program must be 20 or 32 bytes")
        return f"00{len(prog):02x}{prog.hex()}"
    elif witver == 1 and len(prog) == 32:
        # Taproot
        return f"51{len(prog):02x}{prog.hex()}"
    else:
        # other versions: BIP-350 rules; for generality:
        return f"{(0x50+witver):02x}{len(prog):02x}{prog.hex()}"

def build_raw_p2tr_keypath_tx(*,
                              internal: str,
                              privHex: str,
                              prev_txid: str,
                              prev_vout: int,
                              prev_value: int,  #sats
                              to_address: str,
                              send_value: int,  #sats
                              fee: int,  #sats
                              change_address: Optional[str] = None,
                              version: int = 2,
                              locktime: int = 0) -> Dict[str, str]:
    # prevout must be a Taproot (key-path) output for this signer
    prev_spk = p2tr_scriptpubkey(internal)

    # primary output
    to_spk = spk_from_segwit_addr(to_address)
    outs: List[TxOut] = [TxOut(amount_sats=send_value, scriptpubkey=to_spk)]

    change = prev_value - send_value - fee
    if change < 0:
        raise ValueError(f"Insufficient funds: prev_value({prev_value}) < send({send_value}) + fee({fee})")
    if change > 0:
        if change_address:
            change_spk = spk_from_segwit_addr(change_address)
        else:
            # default: send change back to the same Taproot (BIP86) as the input
            change_spk = p2tr_scriptpubkey(internal)
        outs.append(TxOut(amount_sats=change, scriptpubkey=change_spk))

    inp = TxIn(txid=prev_txid, vout=prev_vout, amount_sats=prev_value, prevout_scriptpubkey=prev_spk, sequence=0xFFFFFFFF)

    tx = sign_and_assemble_keypath_all(
        version=version,
        locktime=locktime,
        inputs=[inp],
        outputs=outs,
        input_index=0,
        internal_x_hex=internal,
        seckey_hex=privHex,
        merkle_root_hex="",       # key-path (BIP86)
        aux_rand_hex="00"*32      # deterministic; use fresh randomness ideally
    )
    print("txid  :", tx["txid"])     # non-witness id 
    print("wtxid :", tx["wtxid"])    # witness id
    print("sighash:", tx["sighash"])
    print("sig    :", tx["sig"])
    print("raw   :", tx["raw"])      # `sendrawtransaction`
    return tx
from Crypto.Hash import keccak
from ecdsa.ecdsa import Signature, generator_secp256k1
from eth_account.account import Account
from eth_utils import to_bytes
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type import namedtype, univ


class SPKIAlgorithmIdentifierRecord(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any()),
    )


class SPKIRecord(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", SPKIAlgorithmIdentifierRecord()),
        namedtype.NamedType("subjectPublicKey", univ.BitString()),
    )


class ECDSASignatureRecord(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )


def public_key_int_to_eth_address(pubkey: int):
    hex_string = hex(pubkey).replace("0x", "")
    padded_hex_string = hex_string.replace("0x", "").zfill(130)[2:]

    k = keccak.new(digest_bits=256)
    k.update(bytes.fromhex(padded_hex_string))
    return "0x" + str(bytes.fromhex(k.hexdigest())[-20:].hex()).upper()


def der_encoded_public_key_to_eth_address(pubkey: bytes):
    received_record, _ = der_decode(pubkey, asn1Spec=SPKIRecord())
    return public_key_int_to_eth_address(
        int(received_record["subjectPublicKey"].asBinary(), 2)
    )


def get_sig_r_s(signature: bytes):
    received_record, _ = der_decode(signature, asn1Spec=ECDSASignatureRecord())
    r = int(received_record["r"].prettyPrint())
    s = int(received_record["s"].prettyPrint())

    max_value_on_curve = (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    )

    if 2 * s >= max_value_on_curve:
        # s is on wrong side of curve, flip it
        s = max_value_on_curve - s
    return r, s


def normalize_address(address: str):
    """
    Returns a normalized, all caps address except the 0x at the beginning.
    """
    return "0x" + address.strip()[2:].upper()


# def get_sig_v(signature: bytes, r: int, s: int, expected_address: str):
#     print(len(signature))
#     ecdsa_signature = Signature(r, s)

#     pks = ecdsa_signature.recover_public_keys(
#         r + s, generator_secp256k1
#     )

#     for idx, pk in enumerate(pks):
#         x = int(pk.point.to_bytes("hybrid").hex(), 16)
#         computed_address = public_key_int_to_eth_address(x)
#         print(computed_address, expected_address)
#         if computed_address == expected_address:
#             return 27 + idx

#     raise ValueError("Invalid Signature, cannot compute v, addresses do not match!")


def get_sig_v(msg_hash: bytes, r: int, s: int, expected_address: str):
    acc = Account()
    recovered = acc._recover_hash(msg_hash, vrs=(27, r, s))
    recovered2 = acc._recover_hash(msg_hash, vrs=(28, r, s))

    chain_id = 4
    if normalize_address(recovered) == normalize_address(expected_address):
        return 35 + 0 + (chain_id * 2) # 27
    elif normalize_address(recovered2) == normalize_address(expected_address):
        return 35 + 1 + (chain_id * 2) # 28

    raise ValueError("Invalid Signature, cannot compute v, addresses do not match!")


def get_sig_r_s_v(msg_hash: bytes, signature: bytes, address: str):
    r, s = get_sig_r_s(signature)
    v = get_sig_v(msg_hash, r, s, address)
    return r, s, v

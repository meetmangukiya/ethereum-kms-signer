from Crypto.Hash import keccak
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type import univ, namedtype
from ecdsa.ecdsa import generator_secp256k1, Signature


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


def get_sig_v(signature: bytes, r: int, s: int, expected_address: str):
    ecdsa_signature = Signature(r, s)
    pks = ecdsa_signature.recover_public_keys(
        int(signature.hex(), 16), generator_secp256k1
    )

    for idx, pk in enumerate(pks):
        x = int(pk.point.to_bytes("uncompressed").hex(), 16)
        computed_address = public_key_int_to_eth_address(x)
        if computed_address == expected_address:
            return 27 + idx

    raise ValueError("Invalid Signature, cannot compute v, addresses do not match!")

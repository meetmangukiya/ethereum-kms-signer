from Crypto.Hash import keccak
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type import univ, namedtype


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


def der_encoded_public_key_to_eth_address(pubkey):
    received_record, _ = der_decode(pubkey, asn1Spec=SPKIRecord())
    hex_string = str(hex(int(received_record["subjectPublicKey"].asBinary(), 2)))
    padded_hex_string = hex_string.replace("0x", "").zfill(130)[2:]

    k = keccak.new(digest_bits=256)
    k.update(bytes.fromhex(padded_hex_string))
    return "0x" + str(bytes.fromhex(k.hexdigest())[-20:].hex()).upper()


def get_sig_r_s(signature):
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

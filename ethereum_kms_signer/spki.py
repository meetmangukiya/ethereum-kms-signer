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


def der_encoded_public_key_to_eth_address(pubkey):
    received_record, _ = der_decode(pubkey, asn1Spec=SPKIRecord())
    hex_string = str(hex(int(received_record["subjectPublicKey"].asBinary(), 2)))
    padded_hex_string = hex_string.replace("0x", "").zfill(130)[2:]

    k = keccak.new(digest_bits=256)
    k.update(bytes.fromhex(padded_hex_string))
    return "0x" + str(bytes.fromhex(k.hexdigest())[-20:].hex()).upper()

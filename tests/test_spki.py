from base64 import b64decode
from ethereum_kms_signer.spki import der_encoded_public_key_to_eth_address


def test_der_encoded_public_key_to_eth_address():
    b64_pubkey = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEathta5TrXzFas+l1U10khKWvVf2UzMVsRRy3iNNlHtfB1Xkx2DFQJmS8SDovi8+oxUCMAeS1pNFPOnTbU5YVvQ=="
    pubkey = b64decode(b64_pubkey)
    assert (
        der_encoded_public_key_to_eth_address(pubkey)
        == "0x7117AC214FD4ECEE0994ACD4A65D95E2F24AB14A"
    )

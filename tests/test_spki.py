from base64 import b64decode
from ethereum_kms_signer.spki import der_encoded_public_key_to_eth_address, get_sig_r_s


def test_der_encoded_public_key_to_eth_address():
    b64_pubkey = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEathta5TrXzFas+l1U10khKWvVf2UzMVsRRy3iNNlHtfB1Xkx2DFQJmS8SDovi8+oxUCMAeS1pNFPOnTbU5YVvQ=="
    pubkey = b64decode(b64_pubkey)
    assert (
        der_encoded_public_key_to_eth_address(pubkey)
        == "0x7117AC214FD4ECEE0994ACD4A65D95E2F24AB14A"
    )


def test_get_sig_r_s():
    b64sig = "MEUCID8lr9t+1nCUEBzXEQkmGIbbmrvxuiDMU67CC6AcLmuqAiEAqw3m1A+JYMJS/G8h416DaRJvsZAz8QlTxCphdmY134I="
    assert get_sig_r_s(b64decode(b64sig)) == (
        0x3F25AFDB7ED67094101CD71109261886DB9ABBF1BA20CC53AEC20BA01C2E6BAA,
        0x54F2192BF0769F3DAD0390DE1CA17C95A83F2B567B5796E7FBA7FD166A0061BF,
    )

from base64 import b64decode
from ethereum_kms_signer.spki import (
    der_encoded_public_key_to_eth_address,
    get_sig_r_s,
    get_sig_v,
)


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


def test_get_sig_v():
    assert (
        get_sig_v(
            bytes.fromhex(
                "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
            ),
            0xFA754063B93A288B9A96883FC365EFB9AEE7ECAF632009BAA04FE429E706D50E,
            0x6A8971B06CD37B3DA4AD04BB1298FDA152A41E5C1104FD5D974D5C0A060A5E62,
            "0xE94E130546485B928C9C9B9A5E69EB787172952E",
        )
        == 28
    )

    assert (
        get_sig_v(
            bytes.fromhex(
                "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
            ),
            0x904D320777CEAE0232282CBF6DA3809A678541CDEF7F4F3328242641CEECB0DC,
            0x5B7F7AFE18221049A1E176A89A60B6C10DF8C0E838EDB9B2F11AE1FB50A28271,
            "0xE94E130546485B928C9C9B9A5E69EB787172952E",
        )
        == 27
    )

"""Console script for ethereum_kms_signer."""

import json

import fire

from .kms import SignedTransaction, get_eth_address, sign_transaction


def help() -> None:
    print("ethereum_kms_signer")
    print("=" * len("ethereum_kms_signer"))
    print("Sign ETH transactions with keys stored in AWS KMS")


def sign(key_id: str, data: dict) -> SignedTransaction:
    return sign_transaction(data, key_id)


def main() -> None:
    fire.Fire({"help": help, "address": get_eth_address, "sign": sign})


if __name__ == "__main__":
    main()  # pragma: no cover

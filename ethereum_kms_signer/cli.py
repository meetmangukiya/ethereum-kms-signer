"""Console script for ethereum_kms_signer."""

import json

import boto3
import fire

from .kms import get_eth_address, sign_transaction
from .spki import der_encoded_public_key_to_eth_address


def help():
    print("ethereum_kms_signer")
    print("=" * len("ethereum_kms_signer"))
    print("Sign ETH transactions with keys stored in AWS KMS")


def sign(key_id: str, data: dict):
    return sign_transaction(data, key_id)


def main():
    fire.Fire({"help": help, "address": get_eth_address, "sign": sign})


if __name__ == "__main__":
    main()  # pragma: no cover

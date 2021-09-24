"""Console script for ethereum_kms_signer."""

import fire
import boto3
from .spki import der_encoded_public_key_to_eth_address


def help():
    print("ethereum_kms_signer")
    print("=" * len("ethereum_kms_signer"))
    print("Sign ETH transactions with keys stored in AWS KMS")


def get_eth_address(key_id):
    kms_client = boto3.client("kms")
    pubkey = kms_client.get_public_key(KeyId=key_id)["PublicKey"]
    return der_encoded_public_key_to_eth_address(pubkey)


def test():
    ...


def main():
    fire.Fire({"help": help, "test": test, "address": get_eth_address})


if __name__ == "__main__":
    main()  # pragma: no cover

"""Console script for ethereum_kms_signer."""

import fire

def help():
    print("ethereum_kms_signer")
    print("=" * len("ethereum_kms_signer"))
    print("Sign ETH transactions with keys stored in AWS KMS")

def main():
    fire.Fire({
        "help": help
    })


if __name__ == "__main__":
    main() # pragma: no cover

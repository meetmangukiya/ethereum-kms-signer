"""Console script for ethereum_kms_signer."""

import fire
import boto3
from .spki import der_encoded_public_key_to_eth_address, get_sig_r_s_v
import eth_account.signers.base
from eth_account.messages import SignableMessage
from eth_utils import to_bytes
from hexbytes import HexBytes
from eth_account.datastructures import SignedMessage, SignedTransaction
from eth_account.messages import _hash_eip191_message
from cytoolz import (
    dissoc,
)
from eth_utils.curried import keccak
from eth_account._utils.legacy_transactions import (
    Transaction,
    UnsignedTransaction,
    serializable_unsigned_transaction_from_dict,
    encode_transaction,
)
from eth_account._utils.typed_transactions import (
    TypedTransaction,
)


def help():
    print("ethereum_kms_signer")
    print("=" * len("ethereum_kms_signer"))
    print("Sign ETH transactions with keys stored in AWS KMS")


def get_eth_address(key_id):
    kms_client = boto3.client("kms")
    pubkey = kms_client.get_public_key(KeyId=key_id)["PublicKey"]
    return der_encoded_public_key_to_eth_address(pubkey)


class KmsSigner(eth_account.signers.base.BaseAccount):
    def __init__(self, key_id: str):
        super().__init__()
        self._key_id = key_id
        self._kms_client = boto3.client("kms")

    # https://github.com/ethereum/eth-account/blob/bd3dc2c0e85934b9c47980053d9f1d16a7540990/eth_account/_utils/signing.py#L130
    def _pad_to_eth_word(self, bytes_val):
        return bytes_val.rjust(32, b'\0')

    def _sign_message_signature_der(self, sig: bytes):
        r, s, v = get_sig_r_s_v(sig['Signature'])
        signature_bytes = self._pad_to_eth_word(to_bytes(r)) + self._pad_to_eth_word(to_bytes(s)) + to_bytes(v)
        return r, s, v, signature_bytes

    def _kms_sign(self, digest: bytes):
        sign_res = self._kms_client.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm="ECDSA_SHA_256"
        )
        return sign_res['Signature']

    def _sign_message_hash_with_kms(self, digest: bytes):
        return self._sign_message_signature_der(self._kms_sign(digest))

    def _sign_message(self, digest: bytes):
        r, s, v, signature_bytes = self._sign_message_hash_with_kms(digest)
        return SignedMessage(
            messageHash=HexBytes(digest),
            r=r,
            s=s,
            v=v,
            signature=HexBytes(signature_bytes)
        )

    @property
    def address(self):
        pubkey = self._kms_client.get_public_key(KeyId=self._key_id)["PublicKey"]
        return der_encoded_public_key_to_eth_address(pubkey)

    def signHash(self, message_hash):
        return self._sign_message(message_hash)

    def sign_message(self, message: SignableMessage):
        message_hash = _hash_eip191_message(message)
        return self._sign_message(message_hash)

    def _sign_transction_dict(self, transaction_dict: dict):
        unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction_dict)
        transaction_hash = unsigned_transaction.hash()

        if isinstance(unsigned_transaction, UnsignedTransaction):
            chain_id = None
            (v, r, s) = sign_transaction_hash(eth_key, transaction_hash, chain_id)
        elif isinstance(unsigned_transaction, Transaction):
            chain_id = unsigned_transaction.v
            (v, r, s) = sign_transaction_hash(eth_key, transaction_hash, chain_id)
        elif isinstance(unsigned_transaction, TypedTransaction):
            # Each transaction type dictates its payload, and consequently,
            # all the funky logic around the `v` signature field is both obsolete && incorrect.
            # We want to obtain the raw `v` and delegate to the transaction type itself.
            (v, r, s) = eth_key.sign_msg_hash(transaction_hash).vrs
        else:
            # Cannot happen, but better for code to be defensive + self-documenting.
            raise TypeError("unknown Transaction object: %s" % type(unsigned_transaction))

        # serialize transaction with rlp
        encoded_transaction = encode_transaction(unsigned_transaction, vrs=(v, r, s))

        return (v, r, s, encoded_transaction)

    def signTransaction(self, tx_dict: dict):
        # allow from field, *only* if it matches the private key
        if 'from' in tx_dict:
            if tx_dict['from'] == self.address:
                sanitized_transaction = dissoc(tx_dict, 'from')
            else:
                raise TypeError("from field must match key's %s, but it was %s" % (
                    self.address,
                    tx_dict['from'],
                ))
        else:
            sanitized_transaction = tx_dict

        # sign transaction
        (
            v,
            r,
            s,
            encoded_transaction,
        ) = sign_transaction_dict(account._key_obj, sanitized_transaction)
        transaction_hash = keccak(encoded_transaction)

        return SignedTransaction(
            rawTransaction=HexBytes(encoded_transaction),
            hash=HexBytes(transaction_hash),
            r=r,
            s=s,
            v=v,
        )

        return self.sign_transaction(tx_dict)

    def sign_transaction(self, tx_dict: dict):
        ...


def test():
    return KmsSigner("a9cd3f03-6796-4097-ad7d-c8183ab3a44c").address


import json
from .ethereum_kms_signer import sign_transaction

def sign(key_id: str, data: dict):
    return sign_transaction(data, key_id)

def main():
    fire.Fire({"help": help, "test": test, "address": get_eth_address, "sign": sign})


if __name__ == "__main__":
    main()  # pragma: no cover

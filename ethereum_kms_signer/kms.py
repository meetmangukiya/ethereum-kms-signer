from collections.abc import Mapping
from typing import NamedTuple

import boto3
from toolz import dissoc
from eth_account._utils.legacy_transactions import Transaction
from eth_account._utils.signing import sign_transaction_dict
from eth_utils.curried import keccak
from hexbytes import HexBytes

from .spki import der_encoded_public_key_to_eth_address, get_sig_r_s_v


class Signature:
    """Kinda compatible Signature class"""

    def __init__(self, r, s, v):
        self.r = r
        self.s = s
        self.v = v

    @property
    def vrs(self):
        return [self.v, self.r, self.s]


class SignedTransaction(NamedTuple):
    """Kinda compatible SignedTransaction class"""

    rawTransaction: HexBytes
    hash: HexBytes
    r: int
    s: int
    v: int

    def __getitem__(self, index):
        return __getitem__(self, index)


class BasicKmsAccount:
    """Kinda compatible eth_keys.PrivateKey class"""

    def __init__(self, key_id, address):
        self._key_id = key_id
        self._kms_client = boto3.client("kms")
        self._address = address

    def sign_msg_hash(self, msg_hash: HexBytes) -> Signature:
        signature = self._kms_client.sign(
            KeyId=self._key_id,
            Message=bytes(msg_hash),
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        act_signature = signature["Signature"]
        r, s, v = get_sig_r_s_v(msg_hash, act_signature, self._address)
        return Signature(r, s, v)


def _sign_transaction(transaction_dict, address, kms_account):
    """
    Somewhat fixed up version of Account.sign_transaction, to use the custom PrivateKey
    impl -- BasicKmsAccount
    https://github.com/ethereum/eth-account/blob/master/eth_account/account.py#L619
    """

    if not isinstance(transaction_dict, Mapping):
        raise TypeError("transaction_dict must be dict-like, got %r" % transaction_dict)

    # allow from field, *only* if it matches the private key
    if "from" in transaction_dict:
        if transaction_dict["from"] == address:
            sanitized_transaction = dissoc(transaction_dict, "from")
        else:
            raise TypeError(
                "from field must match key's %s, but it was %s"
                % (
                    address,
                    transaction_dict["from"],
                )
            )
    else:
        sanitized_transaction = transaction_dict

    # sign transaction
    (
        v,
        r,
        s,
        encoded_transaction,
    ) = sign_transaction_dict(kms_account, sanitized_transaction)
    transaction_hash = keccak(encoded_transaction)

    return SignedTransaction(
        rawTransaction=HexBytes(encoded_transaction),
        hash=HexBytes(transaction_hash),
        r=r,
        s=s,
        v=v,
    )


def sign_transaction(tx_obj, key_id):
    """Sign a transaction object with given AWS KMS key."""
    kms_client = boto3.client("kms")
    kms_pub_key_bytes = kms_client.get_public_key(KeyId=key_id)["PublicKey"]
    address = der_encoded_public_key_to_eth_address(kms_pub_key_bytes)
    kms_account = BasicKmsAccount(key_id, address)
    return _sign_transaction(tx_obj, address, kms_account)


def get_eth_address(key_id):
    """Calculate ethereum address for given AWS KMS key."""
    kms_client = boto3.client("kms")
    pubkey = kms_client.get_public_key(KeyId=key_id)["PublicKey"]
    return der_encoded_public_key_to_eth_address(pubkey)

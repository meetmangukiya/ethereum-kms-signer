# Ethereum KMS Signer


<p align="center">
<a href="https://pypi.python.org/pypi/ethereum_kms_signer">
    <img src="https://img.shields.io/pypi/v/ethereum_kms_signer.svg"
        alt = "Release Status">
</a>

<a href="https://github.com/meetmangukiya/ethereum_kms_signer/actions">
    <img src="https://github.com/meetmangukiya/ethereum_kms_signer/actions/workflows/dev.yml/badge.svg?branch=main" alt="CI Status">
</a>

</p>


Sign ETH transactions with keys stored in AWS KMS


* Free software: MIT
* Documentation: <https://meetmangukiya.github.io/ethereum-kms-signer>

## Features

* Sign Transactions

## Video Demo

[![Python Ethereum KMS Signer Demo](https://img.youtube.com/vi/fZ-mtMb2BjY/0.jpg)](https://youtu.be/fZ-mtMb2BjY?t=35s "Python Ethereum KMS Signer Demo")

## Why?

In the crypto world, all the assets, tokens, crypto you might own is
protected by the secrecy of the private key. This leads to a single point
of failure in cases of leaking of private keys or losing keys because of
lack of backup or any number of reasons. It becomes even harder when you want
to share these keys as an organization among many individuals.

Using something like AWS KMS can help with that and can provide full benefits
of all the security features it provides. Sigantures can be created without the key
ever leaving the AWS's infrastructure and could be effectively shared among individuals.

This library provides a simple and an easy-to-use API for using AWS KMS to sign ethereum
transactions and an easy integration with `web3.py` making it practical for using KMS to
manage your private keys.

## Quickstart

### Get ethereum address from KMS key

```python
from ethereum_kms_signer import get_eth_address
address = get_eth_address('THE-AWS-KMS-ID')
print(address)
```

### Sign a transaction object with KMS key

```python
from ethereum_kms_signer import sign_transaction

dai_txn = dai.functions.transfer(
    web3.toChecksumAddress(to_address.lower()), amount
).buildTransaction(
    {
        "nonce": nonce,
    }
)

# Signing the transaction with KMS key
signed_tx = sign_transaction(dai_txn, key_id)

# send transaction
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
```

### Provisioning AWS KMS key with terraform

An `ECC_SECG_P256K1` key can be provisioned using terraform by using the following
configuration along with the aws provider. More details can be found on
[provider docs]()

```tf
resource "aws_kms_key" "my_very_secret_eth_account" {
    description                 = "ETH account #1"
    key_usage                   = "SIGN_VERIFY"
    customer_master_key_spec    = "ECC_SECG_P256K1"
}

resource "aws_kms_alias" "my_very_secret_eth_account" {
    name            = "eth-account-1"
    target_key_id   = aws_kms_key.my_very_secret_eth_account.id
}
```

## Examples

Few examples can be found [here](https://github.com/meetmangukiya/ethereum-kms-signer/tree/main/examples).

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [zillionare/cookiecutter-pypackage](https://github.com/zillionare/cookiecutter-pypackage) project template.

[This article](https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81) has served as a good resource for implementing the functionality

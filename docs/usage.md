# Usage

To use Ethereum KMS Signer in a project

```
    import ethereum_kms_signer
```

## Authentication

The library uses `boto3`, by default you do not need to provide or do anything if:
1. You have config stored in `~/.aws`
2. Have set the relevant environment variables

More info [here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#configuring-credentials).

You can provide the kwarg `kms_client` to which an authenticated kms client instance can be passed.
For instance, if you want to provide keys via local variables you can do:
```python
import boto3
from ethereum_kms_signer import sign_transaction, get_eth_address

ACCESS_KEY = 'access_key'
SECRET_KEY = 'secret_key'
SESSION_TOKEN = 'session_token'

kms_client = boto3.client(
    'kms',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN
)

key_id = 'key_id'
address = get_eth_address(key_id, kms_client)
signed_tx = sign_transaction(tx_obj, key_id, kms_client)
```

## Get ethereum address from KMS key

```python
from ethereum_kms_signer import get_eth_address
address = get_eth_address('THE-AWS-KMS-ID')
print(address)
```

## Sign a transaction object with KMS key

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

## Provisioning AWS KMS key with terraform

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

# Usage

To use Ethereum KMS Signer in a project

```
    import ethereum_kms_signer
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

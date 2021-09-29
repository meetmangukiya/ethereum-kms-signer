import fire
from web3 import Web3

from ethereum_kms_signer.kms import get_eth_address, sign_transaction


def ether_transfer(web3_provider: str, key_id: str, to_address: str, amount: float):
    web3 = Web3(Web3.HTTPProvider(web3_provider))
    self_address = web3.toChecksumAddress(get_eth_address(key_id).lower())
    nonce = web3.eth.get_transaction_count(self_address)

    # build a transaction in a dictionary
    tx = {
        "nonce": nonce,
        "to": to_address,
        "value": web3.toWei(amount, "ether"),
        "gas": 2000000,
        "gasPrice": web3.toWei("50", "gwei"),
    }

    # sign the transaction
    signed_tx = sign_transaction(tx, key_id)

    # send transaction
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

    # get transaction hash
    print("Transaction Hash:", web3.toHex(tx_hash))


if __name__ == "__main__":
    fire.Fire(ether_transfer)

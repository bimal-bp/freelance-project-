from web3 import Web3
from eth_account import Account
import json
from web3 import Web3

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider("HTTP://127.0.0.1:8545"))

# # Select a Ganache account with ETH
rich_account = w3.eth.accounts[1]  # First account (usually has 100 ETH)
employer_wallet = "0xCA5f14aD1810761c3cD8991Cd8640dFc9e3E289a"  # Replace with your employer's wallet

# # Send ETH (5 ETH for contract deployment)
# Send ETH (50 ETH for contract deployment)
txn_hash = w3.eth.send_transaction({
    "from": w3.eth.accounts[0],  # Use the first rich account from Ganache
    "to": employer_wallet,
    "value": w3.to_wei(50, "ether")  # Sending 50 ETH
})

print(f"Transaction Hash: {txn_hash.hex()}")

# # Confirm balance
balance_wei = w3.eth.get_balance(employer_wallet)
balance_eth = w3.from_wei(balance_wei, 'ether')
print(f"Employer Wallet New Balance: {balance_eth} ETH")

class BlockchainInterface:
    def __init__(self, provider_url: str = "HTTP://127.0.0.1:8545"):
        self.w3 = Web3(Web3.HTTPProvider(provider_url))
        
        # Load contract ABI and bytecode
        with open('contracts/FreelanceContract.json', 'r') as f:
            contract_data = json.load(f)
            self.contract_abi = contract_data['abi']
            self.contract_bytecode = contract_data['bytecode']
    
    def create_wallet(self) -> dict:
        """Create a new Ethereum wallet."""
        account = Account.create()
        return {
            'address': account.address,
            'private_key': account.key.hex()
        }
    
    def deploy_contract(self, employer_private_key: str, freelancer_address: str, job_description: str, amount: float) -> str:
        """Deploy a new freelance contract with balance check."""
        try:
            freelancer_checksum_address = self.w3.to_checksum_address(freelancer_address)
            employer_account = Account.from_key(employer_private_key)
            employer_address = employer_account.address

            balance_wei = self.w3.eth.get_balance(employer_address)
            balance_eth = self.w3.from_wei(balance_wei, 'ether')
            print(f"Employer's Wallet Balance: {balance_eth} ETH")

            amount_wei = self.w3.to_wei(amount, 'ether')

            # Adjust gas and gas price
            estimated_gas = 3000000
            gas_price = self.w3.to_wei('20', 'gwei')
            gas_cost = estimated_gas * gas_price
            total_required = gas_cost + amount_wei

            print(f"Gas Cost Estimate: {self.w3.from_wei(gas_cost, 'ether')} ETH")
            print(f"Total Required: {self.w3.from_wei(total_required, 'ether')} ETH")

            if balance_wei < total_required:
                raise Exception("Insufficient funds in employer's wallet! Please add ETH.")

            contract = self.w3.eth.contract(
                abi=self.contract_abi,
                bytecode=self.contract_bytecode
            )

            nonce = self.w3.eth.get_transaction_count(employer_address)

            construct_txn = contract.constructor(
                freelancer_checksum_address,
                job_description
            ).build_transaction({
                'from': employer_address,
                'nonce': nonce,
                'gas': estimated_gas,
                'gasPrice': gas_price,
                'value': amount_wei
            })

            signed_txn = self.w3.eth.account.sign_transaction(construct_txn, employer_private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)  # FIXED
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            print(f"✅ Contract successfully deployed at: {tx_receipt.contractAddress}")
            return tx_receipt.contractAddress

        except Exception as e:
            raise Exception(f"Failed to deploy contract: {str(e)}")


    
    def get_contract(self, contract_address: str):
        """Get contract instance at specified address."""
        return self.w3.eth.contract(
            address=contract_address,
            abi=self.contract_abi
        )
    
    def start_project(self, contract_address: str, freelancer_private_key: str):
        """Start the project (called by freelancer)."""
        contract = self.get_contract(contract_address)
        freelancer_account = Account.from_key(freelancer_private_key)
        
        tx = contract.functions.startProject().build_transaction({
            'from': freelancer_account.address,
            'nonce': self.w3.eth.get_transaction_count(freelancer_account.address),
            'gas': 2000000,
            'gasPrice': self.w3.eth.gas_price
        })
        
        signed_txn = self.w3.eth.account.sign_transaction(tx, freelancer_private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return self.w3.eth.wait_for_transaction_receipt(tx_hash)
    
    def complete_work(self, contract_address: str, freelancer_private_key: str):
        """Mark work as complete (called by freelancer)."""
        contract = self.get_contract(contract_address)
        freelancer_account = Account.from_key(freelancer_private_key)
        
        tx = contract.functions.completeWork().build_transaction({
            'from': freelancer_account.address,
            'nonce': self.w3.eth.get_transaction_count(freelancer_account.address),
            'gas': 2000000,
            'gasPrice': self.w3.eth.gas_price
        })
        
        signed_txn = self.w3.eth.account.sign_transaction(tx, freelancer_private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return self.w3.eth.wait_for_transaction_receipt(tx_hash)
    
    def release_payment(self, contract_address: str, employer_private_key: str):
        """Release payment to freelancer (called by employer)."""
        contract = self.get_contract(contract_address)
        employer_account = Account.from_key(employer_private_key)
        
        tx = contract.functions.releasePayment().build_transaction({
            'from': employer_account.address,
            'nonce': self.w3.eth.get_transaction_count(employer_account.address),
            'gas': 2000000,
            'gasPrice': self.w3.eth.gas_price
        })
        
        signed_txn = self.w3.eth.account.sign_transaction(tx, employer_private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return self.w3.eth.wait_for_transaction_receipt(tx_hash)
    
    
    def get_contract_status(self, contract_address: str) -> dict:
        """Get current contract status and details."""
        contract = self.get_contract(contract_address)
        return {
            'status': contract.functions.getProjectStatus().call(),
            'balance': self.w3.from_wei(contract.functions.getContractBalance().call(), 'ether'),
            'employer': contract.functions.employer().call(),
            'freelancer': contract.functions.freelancer().call(),
            'is_completed': contract.functions.isCompleted().call(),
            'is_paid': contract.functions.isPaid().call()
        }

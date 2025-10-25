# Beep Contract Hedera

## Overview

This a solidity smart contract designed for Hedera intent-based transactions, enabling users to create, fill, and cancel intents for token swaps on Hedera. It supports multi-signature governance, and robust security features like circuit breakers and rate limiting. The contract facilitates secure token transfers, wallet management, and recovery mechanisms while maintaining a flexible configuration for supported tokens and protocols.

A Compliant, Hedera-Powered Stablecoin with Intent-Based swaps for Financial Inclusion in Africa.
`bNGN` is a 1:1 Nigerian Naira-backed stablecoin built on Hedera using the ERC3643 standard for compliant security tokens, integrated with an innovative intent-based trading system (`BeepContract`). It tackles financial exclusion in Africa by enabling regulated, low-cost digital transactions for remittances, payments, and savings. The system ensures KYC/AML compliance, transfer limits, and proof-of-reserves (PoR) while leveraging Hedera's high-throughput, low-cost network. The BeepContract adds intent-based token swaps, allowing users to specify desired trades (e.g., `bNGN` for `HBAR`) with flexible execution by third parties, enhancing liquidity and accessibility.

## Technical Use of Hedera

- **Hedera Token Service (HTS)**: bNGN token creation, minting, burning, and transfers, leveraging 10,000 TPS and < $0.001 fees.
- **Hedera Smart Contract Service**: Deploys ERC3643 and BeepContract on Hedera EVM for compliance and trading logic.
- **Hedera Consensus Service (HCS)**: Timestamps PoR URIs (IPFS) for immutability.
- **Mirror Node**: Real-time queries for balances, intents, and transactions.

_**Why Hedera**_: Fixed low fees, 3-5s finality, and carbon-neutral operation suit Africa's high-volume, cost-sensitive markets.

## Impact

- **Nigeria/Africa Relevance**: Reduces $26B remittance costs (6.5% avg.) by 90%, empowers 40M unbanked Nigerians with compliant wallets, and mitigates NGN volatility.
- **Scalability**: Supports 1M+ users via batch minting and intent-based DeFi.
- **Adoption**: Regulatory compliance enables bank partnerships for fiat ramps.
- **Sustainability**: Aligns with Africa's green finance goals via Hedera's ESG focus.

## Completeness

- **MVP Features**: Token issuance, compliant transfers, ProofOfReserve, KYC/AML, intent-based swaps.
- **Tested**: Foundry suite, deployed on Hedera testnet.
- **Future**: cross-chain intents.

## Presentation
Our 3-min demo video covers the problem (costly remittances, exclusion), solution (bNGN + intents), live demo (mint/transfer/swap), and impact (cost savings, inclusion). See below for details.

## Problem Statement
In Africa, 57% of the population (400M+) is unbanked, and Nigeria's $20B+ remittances face 6.5% fees (World Bank 2023). Volatility in NGN and regulatory restrictions limit digital finance adoption. Existing stablecoins lack compliance for African regulators, risking bans, and cross-token trading is costly and complex. bNGN addresses this with a compliant, Hedera-powered stablecoin and intent-based trading for efficient, low-cost financial access.

## Solution: Beep intent-based wallet and decentralized fiat backed stable coin

**High-Level Architecture**
![graphics/contract-high-level-architecture](<graphics/contract-high-level-architecture.png>)

- **HTS**: bNGN token operations (mint, burn, transfer).
- **Smart Contracts**: ERC3643 for compliance, BeepContract for intents.
- **HCS**: PoR timestamping.
- **Mirror Node**: Real-time intent and balance queries.

## Setup & Usage
**Prerequisites**

- **Node.js**: v16+
- **Foundry**: Latest
- **Hedera Account**: Testnet account with HBAR
Environment:
```bash
    HEDERA_RPC_URL=https://localhost:7546  # For Localnet, or https://testnet.hashio.io/api for Testnet
    HEDERA_PRIVATE_KEY=0x<hedera_private_key>
    AGENT_PRIVATE_KEY=0x<agent_private_key>
    PAUSER_PRIVATE_KEY=0x<pauser_private_key>
    AUDITOR_PRIVATE_KEY=0x<auditor_private_key>
    TRUSTED_ISSUER_PRIVATE_KEY=0x<trusted_issuer_private_key>
    USER_PRIVATE_KEY=0x<user_private_key>
    IDENTITY_CONTRACT_PRIVATE_KEY=0x<identity_contract_private_key>
    INITIAL_RESERVE_PROOF=1000000

    NEW_USER_ADDRESS=0x000000000000000000000000000000000044bf11
    IDENTITY_CONTRACT=0x0a8f5ccC8450ABeB45588909e97611d514B6DcB5
    IDENTITY_REGISTRY=0xDD6AE8Cc2bf530B467E05106C698dEBf9E7cEF9D
    USER_COUNTRY_CODE=234 # Nigeria
    KYC_VERIFICATION_DATA="KYC verified - NIN: 12345678901, DOB: 1990-01-01"
    AML_VERIFICATION_DATA="AML clear - No sanctions matches, Risk: LOW"
```

**Installation**

```bash
git clone https://github.com/BeepFi/beep-contract-hedera
cd beep-contract-hedera
forge install
```

**Testing**

```bash 
forge test
```

**Deployment**

```bash
forge script script/ERC3643.s.sol --rpc-url hedera --broadcast --slow --legacy -vvvv
```

## Security & Best Practices

- **ERC3643**: RWA token enterprise standard, guards, pausable, role-based access.
- **BeepContract**: Input validation, escrow for intents, paymaster for gasless UX.
- **Hedera**: Fixed fees prevent front-running; HCS ensures PoR trust.
- **Tests**: Edge cases (invalid tokens, insufficient balances, expired intents).

## Future Roadmap

Cross-chain intents (e.g. Cosmos, LayerZero, Ethereum, Solana, Polkadot).

## Conclusion
`bNGN` leverages Hedera's scalability and compliance to deliver a transformative stablecoin for Africa. By integrating `ERC3643` with intent-based DeFi activities via `BeepContract`, it offers a scalable, compliant, and user-friendly solution for remittances and financial inclusion. We thank Hedera for enabling this innovation!
# Starknet Staking 



### Contest Details

- Total Pool - $80,000
- H/M -  $75,000
- Low - $5,000

- Starts: April 03, 2025 Noon UTC
- Ends: April 24, 2025 Noon UTC

- nSLOC: 4307

[//]: # (contest-details-open)

## About the Project

This project holds the implementation of Starknet's staking mechanism v2, following Starknet SNIP 28.

### Documentation

- [Docs](https://docs.starknet.io/staking/overview/)
- [GitHub](https://github.com/starkware-libs/starknet-staking)

### Key changes in Staking v2

1. **Validator Block Attestation**: Validators must attest to randomly selected blocks to demonstrate active network participation.
2. **Commission Model Update**: Validators will be able to set a maximum commission rate, ensuring transparency while allowing for economic adjustments.

### Actors

- **Delegator:**
  - Delegates their stake to a Validator and shares rewards.
  - Can move between Validators with an epoch delay.
- **Validator (Previously called Staker):**
  - Runs a full node and attests to blocks.
  - Receives rewards based on successful attestations.
  - Can set a maximum commission rate for delegators.
- **Security Roles:**
  - **Security Admin:** Unpauses contracts and can replace the security agent.
  - **Security Agent:** Can pause staking contracts in case of issues.
- **Operator:** 
  - The only role that can call state-changing functions in the staking core contract.
- **L1 Mint Manager:**
  - Handles minting of STRK as allowed by governance.
  - **AllowanceGovernor:** Can authorize minting.
  - **StopGovernor:** Can restrict minting.

### Key Features of Staking v2

- **Epochs and Reward Mechanism:**
  - Staking v2 introduces epochs to define staking power updates.
  - Validators must successfully attest to assigned blocks within an epoch to earn rewards.
  - Rewards follow an "all or nothing" model per epoch.
- **Block Attestation:**
  - Each Validator is assigned a block per epoch to attest.
  - The attestation must be submitted within a defined block window.
  - Validators who fail to attest receive no rewards for that epoch.
- **Commission Model Updates:**
  - Validators commit to a maximum commission (M) and its validity period.
  - They cannot increase commission beyond M before the commitment expires.
  - The commitment period cannot exceed one year.
- **Backward Compatibility:**
  - Rewards accumulated before the upgrade remain claimable.
  - The reward structure is updated to depend on attestation success.
  - Delegators switching Validators face an epoch delay to prevent rapid changes.
[//]: # (contest-details-close)

[//]: # (scope-open)

## Scope (contracts)

```
└── workspace
    ├── apps
        └── staking
            └── contracts
                ├── src
                    ├── attestation
                    │   ├── attestation.cairo
                    │   ├── errors.cairo
                    │   ├── interface.cairo
                    ├── constants.cairo
                    ├── errors.cairo
                    ├── pool
                    │   ├── eic.cairo
                    │   ├── errors.cairo
                    │   ├── interface.cairo
                    │   ├── objects.cairo
                    │   ├── pool.cairo
                    │   ├── pool_member_balance_trace
                    │   │   └── trace.cairo
                    ├── reward_supplier
                    │   ├── errors.cairo
                    │   ├── interface.cairo
                    │   ├── reward_supplier.cairo
                    ├── staking
                    │   ├── eic.cairo
                    │   ├── errors.cairo
                    │   ├── interface.cairo
                    │   ├── objects.cairo
                    │   ├── staker_balance_trace
                    │   │   └── trace.cairo
                    │   ├── staking.cairo
                    ├── types.cairo
                    └── utils.cairo
```


## Compatibilities

Compatibilities:

  Blockchains:
      - Ethereum/Starknet
  
  Tokens:
      - STRK

[//]: # (scope-close)

[//]: # (getting-started-open)

## Setup

### Dependencies
The project is build with [Turbo repo](https://turbo.build/) and [pnpm](https://pnpm.io/).  
Turbo's installation process will also install the cairo dependencies such as [Scarb](https://docs.swmansion.com/scarb/) and [Starknet foundry](https://foundry-rs.github.io/starknet-foundry/index.html).

### Installation
Clone the repo:
```bash
git clone https://github.com/CodeHawks-Contests/2025-04-starknet-part-2.git
```
and from within the projects root folder run:
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
nvm install 20
curl -fsSL https://get.pnpm.io/install.sh | sh -
pnpm install turbo --global
pnpm install
```

[//]: # (getting-started-close)

[//]: # (known-issues-open)

## Known Issues

None Reported.

[//]: # (known-issues-close)

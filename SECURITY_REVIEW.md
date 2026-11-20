# Security Review: era-system-contracts — Verdict: NO EXPLOITABLE BUG (honest kill)

**Scope:** `github.com/nftboy07/era-system-contracts` @ `3e954a629ad8e01616174bde2218241b360fda0a` (main).
**Goal:** a bug exploitable *today* by an unprivileged attacker, proven by a passing PoC.
**Result:** none found. No PoC is claimed, because no finding exists to prove.

## 1. The repo is an unmodified copy of official upstream

This repository is byte-for-byte identical to the official
`matter-labs/era-system-contracts` main branch at commit `3e954a6`
(2023-09-21, "chore: Syncs common workflows from the template into main (#17)").
There is no planted or locally modified code to target.

Reproduce:

```bash
git clone https://github.com/matter-labs/era-system-contracts upstream-esc
git -C upstream-esc checkout 3e954a6
diff -rq era-system-contracts upstream-esc --exclude=.git; echo "EXIT=$?"
```

Output:

```
EXIT=0
```

Both trees have 82 files; `diff` exits 0. `3e954a6` is an ancestor of upstream `origin/main`.

## 2. Attacker-reachable surface examined

Every `external`/`public` entry point reachable by an unprivileged account was read for
access control and invariant breaks:

| Contract / function | Guard / invariant | Status |
|---|---|---|
| `L2EthToken.transferFromTo` | only MsgValueSimulator / Deployer / bootloader | safe |
| `L2EthToken.mint` | `onlyBootloader` | safe |
| `L2EthToken.withdraw` / `withdrawWithMessage` | burns own `msg.value` only | safe |
| `ImmutableSimulator.setImmutables` | only Deployer | safe |
| `ContractDeployer.forceDeployOnAddresses` | only FORCE_DEPLOYER / ComplexUpgrader | safe |
| `ContractDeployer.forceDeployOnAddress` | `onlySelf` | safe |
| `ContractDeployer.create*/create2*` | `onlySystemCall`; no kernel-space, no redeploy, no occupied-account deploy | safe |
| `ContractDeployer.updateAccountVersion` | keyed on `msg.sender` (own account only) | safe |
| `ContractDeployer.updateNonceOrdering` | own account; one-way Sequential -> Arbitrary | safe |
| `NonceHolder.increaseMinNonce` | own account; increment capped at `MAXIMAL_MIN_NONCE_INCREMENT` | safe |
| `NonceHolder.setValueUnderNonce` | own account; sequential accounts must use previous nonce first | safe |
| `NonceHolder.incrementDeploymentNonce` | only Deployer | safe |
| `DefaultAccount.validate/execute/payFor*` | bootloader-only, no delegatecall; low-`s` enforced, `v` in {27,28}, recovered == `address(this)` | safe |
| `DefaultAccount.executeTransactionFromOutside` | no-op | safe |
| `MsgValueSimulator` fallback | `onlySystemCall`; blocks calls to itself | safe |

Notes:
- `NonceHolder` min-nonce overflow into the deployment-nonce bits would need about 2^96
  maximal increments. That is not feasible.
- `getNewAddressCreate2` binds sender, salt, bytecode hash and constructor-input hash, and its
  prefix differs from Ethereum CREATE/CREATE2. There is no address-collision path.

## 3. Why this cannot be "exploitable today"

- **Already audited and live:** this is production zkSync Era code. It has been through multiple
  professional audits and public contests.
- **Older than deployed code:** the snapshot is 43 commits behind upstream main and older than
  what runs on mainnet. The later commits are CI, docs and Boojum integration work, not
  contract security fixes. A bug that existed only in this snapshot would already be patched
  on mainnet, so it would not be exploitable today.

## 4. Why a plain Foundry/EVM PoC would be invalid here

Access control depends on zkEVM intrinsics. `onlySystemCall`, `isSystemCall()`,
`getCodeAddress()`, `getExtraAbiData()` and `EfficientCall` are `call`/`staticcall` to
magic addresses that `zksolc` (`isSystem: true`) compiles into VM opcodes. On a standard EVM
(forge/anvil) these hit empty addresses and return meaningless values. Any forge "exploit"
against these contracts would show a bypass that cannot happen on zkSync, which is a false
positive. A valid PoC needs `zksolc` 1.3.11 and a zkSync VM (era-test-node or a local zkSync
node), as `yarn test` (`zk f mocha`, `localhost:3050`) already assumes.

## 5. Venue (if a real finding is ever proven)

ZKsync Era bug bounty on Immunefi: https://immunefi.com/bug-bounty/zksyncera/

# Satset

EIP-7702 rescue helper. A sponsor relays a signed claim or transfer so a
delegated EOA can move ERC-20 or native balances to a safe recipient. No fee.

```
  compromised EOA                         safe wallet
  (has tokens / a claim)                  (destination)
         |                                       ^
         |  1. EIP-7702 delegate to Satset       |
         |  2. EIP-712 sign the rescue           |
         |                                       |
         v                                       |
     [ Satset ]  ---- 3. sponsor relays tx ----  |
         |                                       |
         +---- claim (optional) ----> [ airdrop / claim target ]
         |
         +---- sweep full balance ------------->  safeRecipient
```

## Actors

```
  ACCOUNT          EOA that holds (or is about to claim) assets.
                   Signs EIP-7702 delegation + EIP-712 intent.
                   Never pays gas.

  SPONSOR          Relays the signed intent. Pays gas.
                   Bound into the signature (cannot be swapped).

  SAFE RECIPIENT   Wallet that receives the rescued funds.
                   Must not be the account itself.

  SATSET           Implementation contract. Verifies delegation,
                   signature, nonce, deadline — then calls into
                   the delegated EOA to execute.
```

## 1. Delegate (EIP-7702)

The account authorizes `0xef0100 || satset` as its code (23 bytes).
Until revoked, calls to the EOA run Satset bytecode in the EOA's context.

```
  ACCOUNT                         CHAIN
     |                              |
     |  type-0x04 tx / auth list    |
     |  { chainId, satset, nonce }  |
     |----------------------------->|
     |                              |
     |                    extcodesize(account) == 23
     |                    code = ef 01 00 | satset address
     |                              |
     |   account is now a          |
     |   "smart EOA"               |
     v                              v

  +------------------+     +---------------------------+
  | ACCOUNT (EOA)    |     | SATSET (implementation)   |
  | balance, nonce   |     | owner, pause, blocklist   |
  | code: 7702 stub  |---->| executeRecover* / Sweep*  |
  +------------------+     +---------------------------+
           |
           |  address(this) during execute* = ACCOUNT
           |  msg.sender during execute*    = SATSET
```

Satset rejects the relay unless `_verifyDelegation` sees exactly that stub.

## 2. Sign the intent (EIP-712)

The account signs off-chain. Domain `verifyingContract` is the **account**,
not Satset. The digest binds recipient, assets, sponsor, nonce, and deadline.

```
  ACCOUNT (offline)

    domain  = EIP712Domain("Satset", "1", chainId, verifyingContract=ACCOUNT)
    nonce   = accountNonces[ACCOUNT][SPONSOR]
    digest  = keccak256("\x19\x01" || domainSeparator || structHash)
    sig     = sign(accountPk, digest)

  structHash is one of:

    ClaimAndTransfer        recoverERC20
    ClaimAndTransferNative  recoverNative
    TransferToken           sweepERC20
    TransferNative          sweepNative
```

## 3. Relay

Sponsor calls Satset. Satset checks, burns the nonce, then `CALL`s the
delegated account with the matching `execute*` payload.

```
  SPONSOR                SATSET                     ACCOUNT (delegated)
     |                      |                              |
     |  recover* / sweep*   |                              |
     |  + signature         |                              |
     |--------------------->|                              |
     |                      |                              |
     |              [ contract context ]                   |
     |              paused?  blocked?                      |
     |              code == ef0100||satset ?               |
     |              ecrecover(digest) == account ?         |
     |              deadline ok?                           |
     |              nonce++                                |
     |                      |                              |
     |                      |  executeRecover* / Sweep*    |
     |                      |  (msg.value forwarded on     |
     |                      |   recover paths)             |
     |                      |----------------------------->|
     |                      |                              |
     |                      |              [ EOA context ] |
     |                      |              msg.sender must |
     |                      |              be Satset       |
     |                      |                              |
     |                      |<---- revert / success -------|
     |<---------------------|                              |
```

## Recover — claim, then sweep

Use when the account is owed tokens or ETH at a claim target (airdrop,
vesting, etc.) and should not leave anything on the compromised key.

```
  recoverERC20 / recoverNative
  ────────────────────────────────────────────────────────────────

  SPONSOR ---- recoverERC20(account, safe, token, claimTarget,
  |             claimData, deadline, sig) ------------------+
  |                                                         |
  |                                                         v
  |                                                   [ SATSET ]
  |                                                         |
  |                              executeRecoverERC20        |
  |                              (safe, token, target, data)|
  |                                                         v
  |                                                   [ ACCOUNT ]
  |                                                         |
  |              1. claimTarget.call(claimData)             |
  |                 tokens/ETH land on ACCOUNT              |
  |                         |                               |
  |                         v                               |
  |              +------------------+     +--------------+  |
  |              | CLAIM TARGET     |     | TOKEN / ETH  |  |
  |              | airdrop.claim()  |---->| mint/transfer|
  |              +------------------+     | to ACCOUNT   |  |
  |                                       +--------------+  |
  |                                                         |
  |              2. full balanceOf(ACCOUNT) / ACCOUNT.balance
  |                 -> safeRecipient                        |
  |                         |                               |
  |                         v                               |
  |              +------------------+                       |
  |              | SAFE RECIPIENT   |  ACCOUNT left at 0    |
  |              | gets everything  |  emit Rescued         |
  |              +------------------+                       |
```

`claimData` is opaque calldata (e.g. merkle `claim(amount, validFrom, proof)`).
If the claim call fails, the whole tx reverts (`ClaimFailed`). Pre-existing
token/ETH balance on the account is swept in the same step.

## Sweep — move what is already there

No claim. Moves balances the EOA already holds.

```
  sweepERC20                         sweepNative
  ────────────────────               ────────────────────

  SPONSOR                            SPONSOR
     |                                  |
     | sweepERC20(                      | sweepNative(
     |   account, safe,                 |   account, safe,
     |   tokens[], deadline, sig)       |   deadline, sig)
     v                                  v
  [ SATSET ]                         [ SATSET ]
     |                                  |
     | executeSweepERC20                | executeSweepNative
     v                                  v
  [ ACCOUNT ]                        [ ACCOUNT ]
     |                                  |
     | for each token (max 50):         | amount = this.balance
     |   bal = balanceOf(this)          | safe.call{value: amount}
     |   if bal > 0: transfer           |
     |                                  |
     v                                  v
  SAFE RECIPIENT                     SAFE RECIPIENT
  (only tokens with bal > 0)         (entire ETH balance)
```

At least one transfer must succeed or the call reverts `NoBalance`.

## Paths at a glance

```
                    +------------------ EIP-712 ------------------+
                    |  signed by ACCOUNT, relayed by SPONSOR      |
                    +---------------------------------------------+
                                          |
                    +---------------------+---------------------+
                    |                     |                     |
                    v                     v                     v
              recoverERC20          recoverNative          sweepERC20
              recoverNative                                sweepNative
                    |                     |
                    |  claim first        |  no claim
                    v                     v
              claimTarget.call      transfer full
              then transfer         ACCOUNT balance
              full balance          to safeRecipient
```

## Replay and binding

```
  signature is bound to:

    safeRecipient   token / tokensHash   claimTarget + claimDataHash
    satset          sponsor              nonce   deadline   chainId
    verifyingContract = ACCOUNT

  accountNonces[account][sponsor]  +=  1   on success

  same sig  +  same sponsor     ->  InvalidSignature (nonce moved)
  same sig  +  other sponsor    ->  InvalidSignature (sponsor in digest)
  expired deadline              ->  SignatureExpired
  no 7702 stub to this Satset   ->  NotDelegatedToSatset
```

## Control plane

Owner actions run on the implementation (`onlySelf` + `onlyOwner`).
They do not execute in a delegated EOA.

```
  OWNER ---- pause / unpause ---------> SATSET.paused
       ---- restrictAccount / allow --> SATSET.blocked[account]
       ---- changeOwner --------------> SATSET.owner

  blocked or paused  =>  relay entry points revert
```

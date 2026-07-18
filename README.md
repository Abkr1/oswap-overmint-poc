# PoC — OSWAP over-mint via `vote_shares` without emission settlement

Runnable Proof of Concept for the Obyte / OSWAP token AA finding. It complies with Immunefi's
[Web3 PoC Guidelines](https://immunefisupport.zendesk.com/hc/en-us/articles/9946217628561-Proof-of-Concept-PoC-Guidelines-and-Rules):
it deploys the **real in-scope source** (`oswap.oscript` + `oswap-lib.oscript`) into a **local** Obyte
network and executes the actual attacker transactions, printing the funds over-minted. No mainnet/testnet
interaction.

> Obyte has no EVM, so the Immunefi [forge-poc-templates](https://github.com/immunefi-team/forge-poc-templates)
> (Foundry) do not apply directly. The Obyte-native equivalent of a "forked-mainnet Foundry test" is
> **aa-testkit**, the framework the in-scope repo itself uses for all of its tests; it spins up a local
> DAG (genesis + witness + hub + nodes) and deploys the actual AA source. This PoC is a new test file in
> that same harness.

## What it proves

The attacker (an unprivileged user) becomes the sole staker and the sole LP of two whitelisted pools,
then:

1. lets one emission window accrue with all voting power on pool1;
2. harvests pool1 — **legitimate** (pool1 held the VP all window);
3. `vote_shares` moves all VP pool1 → pool2 — **this handler does not settle emissions**;
4. harvests pool2 — pool2 pays the **same window** at full share although it held **0 VP** during it.

Result: total OSWAP minted to the attacker `R1 + R2 ≈ 2 × E` while the scheduled LP emission for the
window is `E` → `Σ received_emissions > lp_emissions` (unauthorized mint). The excess is created by
`$increase_supply`, diluting the reserve-backed value of every OSWAP holder.

## Dependencies / environment

- **Node.js 16.x** (recommended; aa-testkit's transitive native deps — e.g. `secp256k1@3` — build reliably on 16). Use `nvm install 16 && nvm use 16`.
- **git**, and a **C/C++ build toolchain** for native modules: `python3`, `make`, `g++` (Debian/Ubuntu: `sudo apt-get install -y build-essential python3`).
- **yarn** (or npm).
- Repo dev-deps (already declared in the repo's `package.json`): `aa-testkit` (git dependency `git+https://github.com/valyakin/aa-testkit.git`), `chai`, `mocha`. No API keys or `.env` are required — the network is entirely local and ephemeral (written under `./testdata`).

## Setup & run (copy-paste)

```bash
# 1. get the in-scope source
git clone https://github.com/byteball/oswap-token-aa
cd oswap-token-aa

# 2. drop the PoC into the repo's test folder (it reads ../oswap.oscript and ../oswap-lib.oscript)
cp /path/to/overmint.test.oscript.js test/overmint.test.oscript.js

# 3. install (Node 16)
nvm use 16
yarn                      # or: npm install

# 4. run only this PoC
npx mocha --opts test/mocha.opts test/overmint.test.oscript.js
```

## Expected output (illustrative)

```
=== baseline ===
supply                : <S>
lp_emissions (cum.)   : <L0>

=== exploit result ===
scheduled LP emission for window (E) : <E>
R1 pool1 reward (legit)              : <~E>
R2 pool2 reward (STOLEN)             : <~E>
total minted to attacker (R1+R2)     : <~2E>
over-mint (minted - E)               : <~E>
over-mint ratio                      : 2.00x
supply after                         : <S + ~2E>   (was <S>)
```

Assertions that encode the impact: `R2 ≈ R1` (pool2 stole ~the same window pool1 legitimately earned)
and `R1 + R2 > 1.5 × E` (total minted exceeds the scheduled LP emission → `Σ received > lp_emissions`).

With N sole-farmed pools the same VP is chained through each pool before harvest, giving over-mint
`(N − 1) × f × E` per window (`f` = attacker VP share).

## Funds at risk

- The live AA `OSWAPWKOXZKJPYWATNK47LRDV4UN4K7H` holds **≈ 11,827 GBYTE** of bonding-curve reserve backing the OSWAP supply. At a GBYTE price of ≈ $5 (spot range ~$4.70–$6.26 at time of writing), that is **≈ $59,000** of reserve exposed to dilution; the submitter should recompute `reserve_GBYTE × GBYTE_spot` at submission time.
- **Realistic loss rate (the actual over-mint):** bounded by the live LP-emission stream `= (1 − stakers_share) × inflation_rate = 5% × 5% = 0.25%/yr` of supply, times the attacker's VP share and the number of stale pools. Worked example (`f = 0.5`, `N = 6`, 30-day windows): ≈ **0.6% of supply per year** of pure over-mint (≈ $350/yr at the reserve above), scaling to low-single-digit %/yr (low thousands of USD/yr) at aggressive settings. This is a permanent, repeatable, unprivileged dilution rather than a one-shot drain — reported honestly so the impact is not overstated.

## Compliance notes (Immunefi Web3 PoC rules)

- Deploys and runs the **actual in-scope contract source** (not a model / re-implementation).
- **Runnable code**, not screenshots; **complete**, not a skeleton (all deploy/whitelist/stake/deposit/vote/withdraw steps included, verbatim from the repo's own passing tests).
- **Local only** — no public testnet/mainnet interaction; no DoS.
- **Clear print statements** of supply before/after and per-pool minted rewards, showing the funds over-minted.
- **Funds-at-risk** provided above (tokens × price).

**Author's caveat (please heed before submitting):** aa-testkit requires a full local Obyte toolchain
that could not be stood up in the environment where this PoC was authored, so it was written — verbatim
against the repository's own test conventions — but **not executed here**. Per Immunefi's rule *"do not
submit a partial or incomplete PoC,"* run it locally on Node 16 and confirm the assertions/printout
before attaching it to the report.

## Supplementary

`oswap_overmint_sim.js` (numerical) re-implements the exact `oswap-lib.oscript` emission formulas and
call order and reproduces the 2× over-mint independently of the DAG. It is provided as a cross-check of
the arithmetic, **not** as the primary PoC (the aa-testkit test above is).

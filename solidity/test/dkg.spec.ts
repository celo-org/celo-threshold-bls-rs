import { use, expect, assert } from 'chai'
import { ethers } from "ethers"

import { deployContract, solidity } from 'ethereum-waffle'
import { waffle } from "@nomiclabs/buidler";

// The actual contract
import DKG from "../build/DKG.json"

use(solidity);


describe('DKG', () => {
    const provider = waffle.provider;
    const [deployer, ...participants] = provider.getWallets();

    const timeTravel = async (blocks: number) => {
      for (let i = 0; i < blocks; i++) {
        await provider.send('evm_mine', [])
      }
    }

    // Each phase's data is just an opaque blob of data from the smart contract's
    // perspective, so we'll just use a dummy data object
    const data = "0x2222222222222222222222222222222222222222222222222222222222222222"

    // Each phase lasts 30 blocks
    const PHASE_DURATION = 30;
    const THRESHOLD = 3;

    let dkg: ethers.Contract;

    beforeEach(async () => {
        dkg = await deployContract(deployer, DKG, [THRESHOLD, PHASE_DURATION]);
        await dkg.allowlist(participants[0].address)
        await dkg.allowlist(participants[1].address)
    })

    describe('Whitelist', async () => {
        it('only owner can allowlist', async () => {
            // non-owner user tries to allowlist a sybil copy of them
            dkg = dkg.connect(participants[0]);
            await expect(dkg.allowlist(participants[2].address)).revertedWith("only owner may allowlist users")
        })

        it('owner cannot allowlist twice', async () => {
            await expect(dkg.allowlist(participants[0].address)).revertedWith("user is already allowlisted")
        })

        it('cannot allowlist once started', async () => {
            await dkg.start()
            await expect(dkg.allowlist(participants[2].address)).revertedWith("DKG has already started")
        });
    })

    describe('Registration', async () => {
        it('participants can register', async () => {
            dkg = dkg.connect(participants[0]);
            await dkg.register(data)
        })

        it('participants cannot register if not allowlisted', async () => {
            dkg = dkg.connect(participants[2]);
            await expect(dkg.register(data)).revertedWith("user is not allowlisted or has already registered")
        })

        it('participants cannot register twice', async () => {
            dkg = dkg.connect(participants[0]);
            await dkg.register(data)
            await expect(dkg.register(data)).revertedWith("user is not allowlisted or has already registered")

            // user cannot try to inflate the registrations array with 0-length registrations
            await expect(dkg.register("0x")).revertedWith("user is not allowlisted or has already registered")
        })

        it('cannot register once started', async () => {
            // user is allowlisted but they dont' register in time
            await dkg.allowlist(participants[2].address)
            await dkg.start()

            dkg = dkg.connect(participants[2]);
            await expect(dkg.register(data)).revertedWith("DKG has already started")
        });

        it('only owner can start the DKG', async () => {
            await expect(dkg.connect(participants[0]).start()).revertedWith("only owner may start the DKG")
        });

        it('cannot publish if not registered', async () => {
            expect(dkg.connect(participants[1]).publish(data)).revertedWith("you are not registered!");
        })

    })

    it('e2e', async() => {
        const pubkey1 = "0x123";
        await dkg.connect(participants[0]).register(pubkey1)

        const pubkey2 = "0x456";
        await dkg.connect(participants[1]).register(pubkey2)

        expect(await dkg.inPhase()).to.equal(0);

        await dkg.start()

        expect(await dkg.inPhase()).to.equal(1);

        // only the second participant publishes their shares
        const my_shares = "0x123456";
        await dkg.connect(participants[1]).publish(my_shares)

        const shares = await dkg.getShares()
        expect(shares[0]).to.equal("0x")
        expect(shares[1]).to.equal(my_shares)

        await timeTravel(PHASE_DURATION)
        expect(await dkg.inPhase()).to.equal(2);

        // only the second participant publishes their responses
        const my_responses = "0x234567";
        await dkg.connect(participants[1]).publish(my_responses)

        const responses = await dkg.getResponses()
        expect(responses[0]).to.equal("0x")
        expect(responses[1]).to.equal(my_responses)

        await timeTravel(PHASE_DURATION)
        expect(await dkg.inPhase()).to.equal(3);

        // only the second participant publishes their justifications
        const my_justifications = "0x345678";
        await dkg.connect(participants[1]).publish(my_justifications)

        const justifications = await dkg.getJustifications()
        expect(justifications[0]).to.equal("0x")
        expect(justifications[1]).to.equal(my_justifications)

        await timeTravel(PHASE_DURATION)
        await expect(dkg.inPhase()).revertedWith("VM Exception while processing transaction: revert DKG Ended")
    })

    describe('Shares', async () => {
        beforeEach(async () => {
            dkg = dkg.connect(participants[0])
            await dkg.register(data)

            await dkg.connect(deployer).start()
        })

        it('publishes to shares', async () => {
            await dkg.publish(data)
            const shares = await dkg.getShares()
            expect(shares[0]).to.equal(data)

            const responses = await dkg.getResponses()
            expect(responses[0]).to.equal("0x");

            const justifications = await dkg.getJustifications()
            expect(justifications[0]).to.equal("0x");
        })

        it('cannot publish to shares twice', async () => {
            await dkg.publish(data)
            await expect(dkg.publish(data)).revertedWith("you have already published your shares")
        })
    })

    describe('Responses', async () => {
        beforeEach(async () => {
            dkg = dkg.connect(participants[0])
            await dkg.register(data)

            await dkg.connect(deployer).start()

            await timeTravel(PHASE_DURATION)
        })

        it('publishes to responses', async () => {
            await dkg.publish(data)
            const responses = await dkg.getResponses()
            expect(responses[0]).to.equal(data)

            const shares = await dkg.getShares()
            expect(shares[0]).to.equal("0x");

            const justifications = await dkg.getJustifications()
            expect(justifications[0]).to.equal("0x");

        })

        it('cannot publish twice', async () => {
            await dkg.publish(data)
            await expect(dkg.publish(data)).revertedWith("you have already published your responses")
        })
    })

    describe('Responses', async () => {
        beforeEach(async () => {
            dkg = dkg.connect(participants[0])
            await dkg.register(data)

            await dkg.connect(deployer).start()

            await timeTravel(2 * PHASE_DURATION)
        })

        it('publishes to justifications', async () => {
            await dkg.publish(data)
            const justifications = await dkg.getJustifications()
            expect(justifications[0]).to.equal(data)

            const shares = await dkg.getShares()
            expect(shares[0]).to.equal("0x");

            const responses = await dkg.getResponses()
            expect(responses[0]).to.equal("0x");

        })

        it('cannot publish twice', async () => {
            await dkg.publish(data)
            await expect(dkg.publish(data)).revertedWith("you have already published your justifications")
        })
    })

    it('Phases are correct', async () => {
        expect(await dkg.inPhase()).to.equal(0);
        await dkg.start()
        expect(await dkg.inPhase()).to.equal(1);
        // we need to mine 1 extra block here for the phase to change
        await timeTravel(PHASE_DURATION+ 1)
        expect(await dkg.inPhase()).to.equal(2);
        await timeTravel(PHASE_DURATION + 1)
        expect(await dkg.inPhase()).to.equal(3);
        await timeTravel(PHASE_DURATION + 1)
        await expect(dkg.inPhase()).revertedWith("VM Exception while processing transaction: revert DKG Ended")
    })

    it('Ended', async () => {
        dkg = dkg.connect(participants[0])
        await dkg.register(data)
        await dkg.connect(deployer).start()
        await timeTravel(3 * PHASE_DURATION)
        await expect(dkg.publish(data)).revertedWith("DKG has ended")
    })
})

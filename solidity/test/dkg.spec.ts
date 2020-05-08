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

    let dkg: ethers.Contract;

    beforeEach(async () => {
        dkg = await deployContract(deployer, DKG, [PHASE_DURATION]);
    })

    describe('Registration', async () => {
        it('participants can register', async () => {
            await dkg.register(data)
        })

        it('participants cannot register twice', async () => {
            await dkg.register(data)
            await expect(dkg.register(data)).revertedWith("user is already registered")
        })

        it('cannot register once started', async () => {
            await dkg.start()
            await expect(dkg.register(data)).revertedWith("DKG has already started")
        });

        it('only owner can start the DKG', async () => {
            await expect(dkg.connect(participants[0]).start()).revertedWith("only contract deployer may start the DKG")
        });

        it('cannot publish if not registered', async () => {
            expect(dkg.connect(participants[1]).publish(data)).revertedWith("you are not registered!");
        })
    })

    describe('Shares', async () => {
        beforeEach(async () => {
            dkg = dkg.connect(participants[0])
            await dkg.register(data)

            await dkg.connect(deployer).start()
        })

        // TODO: Why does `dkg.shares()` hang? Is this a buidlerevm issue?
        it.skip('publishes to shares', async () => {
            await dkg.publish(data)
            const shares = await dkg.shares(participants[0]).call();
            expect(shares).to.equal(data)
        })


        it('cannot publish to shares twice', async () => {
            await dkg.publish(data)
            await expect(dkg.publish(data)).revertedWith("you have already published your shares")
        })
    })

    // TODO: Timetravel to each of the other periods
})

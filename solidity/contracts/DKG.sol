pragma solidity ^0.6.6;

import "@nomiclabs/buidler/console.sol";


contract DKG {
    mapping(address => bytes) public keys;

    mapping(address => bytes) public shares;

    mapping(address => bytes) public responses;

    mapping(address => bytes) public justifications;

    uint256 immutable PHASE_DURATION;

    uint256 public startBlock = 0;

    address owner;

    modifier onlyRegistered() {
        require(keys[msg.sender].length > 0, "you are not registered!");
        _;
    }

    modifier onlyWhenNotStarted() {
        require(startBlock == 0, "DKG has already started");
        _;
    }

    constructor(uint256 duration) public {
        PHASE_DURATION = duration;
        owner = msg.sender;
    }

    /// Kickoff function which starts the counter
    function start() external onlyWhenNotStarted {
        require(
            msg.sender == owner,
            "only contract deployer may start the DKG"
        );
        startBlock = block.number;
    }

    /// This function ties a DKG participant's on-chain address with their BLS Public Key
    function register(bytes calldata blsPublicKey) external onlyWhenNotStarted {
        require(keys[msg.sender].length == 0, "user is already registered");
        keys[msg.sender] = blsPublicKey;
    }

    /// Participant publishes their data nand depending on the time it gets
    function publish(bytes calldata value) external onlyRegistered {
        uint256 blocksSinceStart = block.number - startBlock;

        if (blocksSinceStart <= PHASE_DURATION) {
            require(
                shares[msg.sender].length == 0,
                "you have already published your shares"
            );
            shares[msg.sender] = value;
        } else if (blocksSinceStart <= 2 * PHASE_DURATION) {
            require(
                responses[msg.sender].length == 0,
                "you have already published your responses"
            );
            responses[msg.sender] = value;
        } else if (blocksSinceStart <= 3 * PHASE_DURATION) {
            require(
                justifications[msg.sender].length == 0,
                "you have already published your justifications"
            );
            justifications[msg.sender] = value;
        } else {
            revert("DKG has ended");
        }
    }
}

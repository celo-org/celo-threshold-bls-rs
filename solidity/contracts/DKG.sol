// Using the ABIEncoderV2 poses little risk here because we only use it for fetching the byte arrays
// of shares/responses/justifications
pragma experimental ABIEncoderV2;
pragma solidity ^0.6.6;

import "@nomiclabs/buidler/console.sol";


contract DKG {
    mapping(address => bytes) public keys;

    mapping(address => bytes) public shares;

    mapping(address => bytes) public responses;

    mapping(address => bytes) public justifications;

    address[] public participants;

    uint256 immutable PHASE_DURATION;

    uint256 public startBlock = 0;

    address public owner;

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
        participants.push(msg.sender);
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

    // Helpers to fetch data in the mappings

    function getShares() external view returns (bytes[] memory) {
        bytes[] memory _shares = new bytes[](participants.length);
        for (uint256 i = 0; i < participants.length; i++) {
            _shares[i] = shares[participants[i]];
        }

        return _shares;
    }

    function getResponses() external view returns (bytes[] memory) {
        bytes[] memory _responses = new bytes[](participants.length);
        for (uint256 i = 0; i < participants.length; i++) {
            _responses[i] = responses[participants[i]];
        }

        return _responses;
    }

    function getJustifications() external view returns (bytes[] memory) {
        bytes[] memory _justifications = new bytes[](participants.length);
        for (uint256 i = 0; i < participants.length; i++) {
            _justifications[i] = justifications[participants[i]];
        }

        return _justifications;
    }
}

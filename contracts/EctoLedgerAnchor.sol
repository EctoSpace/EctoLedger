// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  EctoLedgerAnchor
/// @notice On-chain anchor registry for Ecto Ledger session hashes.
///
/// Deploying this contract and setting EVM_CONTRACT_ADDRESS allows the Ecto Ledger runtime
/// to commit an immutable, block-timestamped record of any session's ledger tip hash to
/// an Ethereum-compatible chain.  The emitted `Anchored` event can be verified by anyone
/// with access to the chain, providing a cryptographic proof that the session existed at
/// (or before) the block's timestamp — without leaking any session data on-chain.
///
/// ## Usage (Ecto Ledger side)
///
/// Set the following environment variables before starting `ectoledger`:
///
///   EVM_RPC_URL=https://mainnet.infura.io/v3/<KEY>
///   EVM_CHAIN_ID=1
///   EVM_CONTRACT_ADDRESS=0x<deployed address>
///   EVM_PRIVATE_KEY=<32-byte hex private key>
///
/// Then run:
///
///   ectoledger anchor-session <session-uuid> --chain ethereum
///
/// ## Deployment
///
/// Compile and deploy with Foundry:
///
///   forge create contracts/EctoLedgerAnchor.sol:EctoLedgerAnchor \
///         --rpc-url $EVM_RPC_URL \
///         --private-key $EVM_PRIVATE_KEY
///
/// Or with Hardhat:
///
///   npx hardhat run scripts/deploy.js --network mainnet
///
/// ## ABI selector
///
/// `anchor(bytes32)` → keccak256 selector: 0x6b4c3b9d
/// (Verified with: `cast sig "anchor(bytes32)"`)
contract EctoLedgerAnchor {
    // ── Events ────────────────────────────────────────────────────────────────

    /// @notice Emitted each time a session hash is anchored on-chain.
    /// @param sessionHash   SHA-256 ledger tip hash of the Ecto Ledger session (32 bytes).
    /// @param submitter     Address that called `anchor()`.
    /// @param timestamp     `block.timestamp` at the time of anchoring (Unix seconds).
    event Anchored(
        bytes32 indexed sessionHash,
        address indexed submitter,
        uint256 timestamp
    );

    // ── Access-control events ─────────────────────────────────────────────────

    event SubmitterAdded(address indexed submitter);
    event SubmitterRemoved(address indexed submitter);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ── Storage ───────────────────────────────────────────────────────────────

    /// @notice Returns the block timestamp when `sessionHash` was first anchored,
    ///         or zero if the hash has never been anchored.
    mapping(bytes32 => uint256) public anchoredAt;

    /// @notice Contract owner (deployer) — can manage authorized submitters.
    address public owner;

    /// @notice Pending new owner for two-step transfer.
    address public pendingOwner;

    /// @notice Authorized submitters allowed to call `anchor()`.
    mapping(address => bool) public authorizedSubmitters;

    // ── Modifiers ─────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "EctoLedgerAnchor: caller is not the owner");
        _;
    }

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || authorizedSubmitters[msg.sender],
            "EctoLedgerAnchor: caller is not authorized"
        );
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        authorizedSubmitters[msg.sender] = true;
    }

    // ── Access control ────────────────────────────────────────────────────────

    /// @notice Authorize a new submitter address.
    function addSubmitter(address submitter) external onlyOwner {
        authorizedSubmitters[submitter] = true;
        emit SubmitterAdded(submitter);
    }

    /// @notice Revoke a submitter's authorization.
    function removeSubmitter(address submitter) external onlyOwner {
        authorizedSubmitters[submitter] = false;
        emit SubmitterRemoved(submitter);
    }

    /// @notice Start a two-step ownership transfer.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "EctoLedgerAnchor: new owner is the zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Accept the ownership transfer (must be called by the pending owner).
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "EctoLedgerAnchor: caller is not the pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // ── Functions ─────────────────────────────────────────────────────────────

    /// @notice Anchor a 32-byte session hash on-chain.
    ///
    /// Only the contract owner or explicitly authorized submitter addresses
    /// may call this function, preventing front-running and log pollution.
    ///
    /// Subsequent calls with the same `sessionHash` are accepted (idempotent) but
    /// will emit a new `Anchored` event each time, allowing multiple confirmations
    /// to be recorded.  The `anchoredAt` mapping stores only the **first** anchor
    /// timestamp for each hash to preserve the earliest provable existence date.
    ///
    /// @param sessionHash   SHA-256 ledger tip hash produced by `ectoledger`.
    function anchor(bytes32 sessionHash) external onlyAuthorized {
        // Record the earliest anchoring timestamp (first-write-wins).
        if (anchoredAt[sessionHash] == 0) {
            anchoredAt[sessionHash] = block.timestamp;
        }
        emit Anchored(sessionHash, msg.sender, block.timestamp);
    }

    /// @notice Look up when a session hash was first anchored.
    ///
    /// @param sessionHash   SHA-256 ledger tip hash to query.
    /// @return timestamp    Unix timestamp of the first anchor, or 0 if never anchored.
    function getAnchorTime(bytes32 sessionHash) external view returns (uint256) {
        return anchoredAt[sessionHash];
    }
}

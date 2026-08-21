// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title MockClaimableAirdrop
/// @notice Non-upgradeable mock of Aligned's ClaimableAirdrop, used as Satset's
///         `claimTarget`. Claim surface, leaf hashing, and Merkle verification
///         match the production contract so `claim` / `claimBatch` calldata is
///         interchangeable.
contract MockClaimableAirdrop {
    address public owner;
    address public tokenProxy;
    address public tokenDistributor;
    uint256 public limitTimestampToClaim;
    bytes32 public claimMerkleRoot;
    bool public paused;

    mapping(bytes32 => bool) public hasClaimed;

    uint256 private _locked = 1;

    event TokensClaimed(address indexed to, uint256 indexed amount);
    event MerkleRootUpdated(bytes32 indexed newRoot);
    event ClaimPeriodExtended(uint256 indexed newTimestamp);
    event Paused(address account);
    event Unpaused(address account);

    error Unauthorized();
    error Reentrancy();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(paused, "Pausable: not paused");
        _;
    }

    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }

    /// @dev Mirrors `initialize`: starts paused with an empty root and no claim window.
    constructor(address _foundation, address _tokenProxy, address _tokenDistributor) {
        require(_foundation != address(0), "Invalid foundation address");
        require(_tokenProxy != address(0), "Invalid token contract address");
        require(_tokenDistributor != address(0), "Invalid token owner address");

        owner = _foundation;
        tokenProxy = _tokenProxy;
        tokenDistributor = _tokenDistributor;
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Claim tokens for a single vesting stage.
    /// forge-lint: disable-next-item(block-timestamp, erc20-unchecked-transfer)
    function claim(uint256 amount, uint256 validFrom, bytes32[] calldata merkleProof)
        external
        nonReentrant
        whenNotPaused
    {
        require(block.timestamp <= limitTimestampToClaim, "Drop is no longer claimable");

        _verifyAndMark(amount, validFrom, merkleProof);

        IERC20Like(tokenProxy).transferFrom(tokenDistributor, msg.sender, amount);

        emit TokensClaimed(msg.sender, amount);
    }

    /// @notice Claim tokens for multiple vesting stages in a single transaction.
    /// forge-lint: disable-next-item(block-timestamp, erc20-unchecked-transfer)
    function claimBatch(uint256[] calldata amounts, uint256[] calldata validFroms, bytes32[][] calldata merkleProofs)
        external
        nonReentrant
        whenNotPaused
    {
        require(block.timestamp <= limitTimestampToClaim, "Drop is no longer claimable");
        uint256 length = amounts.length;
        require(length == validFroms.length && length == merkleProofs.length, "Array length mismatch");

        uint256 totalClaimable = 0;

        for (uint256 i = 0; i < length; i++) {
            _verifyAndMark(amounts[i], validFroms[i], merkleProofs[i]);
            totalClaimable += amounts[i];
        }

        require(totalClaimable > 0, "Nothing to claim");

        IERC20Like(tokenProxy).transferFrom(tokenDistributor, msg.sender, totalClaimable);

        emit TokensClaimed(msg.sender, totalClaimable);
    }

    function updateMerkleRoot(bytes32 newRoot) external whenPaused onlyOwner {
        require(newRoot != 0 && newRoot != claimMerkleRoot, "Invalid root");
        claimMerkleRoot = newRoot;
        emit MerkleRootUpdated(newRoot);
    }

    function extendClaimPeriod(uint256 newTimestamp) external whenPaused onlyOwner {
        require(
            newTimestamp > limitTimestampToClaim
            /// forge-lint: disable-next-line(block-timestamp)
            && newTimestamp > block.timestamp,
            "Can only extend from current timestamp"
        );
        limitTimestampToClaim = newTimestamp;
        emit ClaimPeriodExtended(newTimestamp);
    }

    function pause() external onlyOwner {
        require(!paused, "Pausable: paused");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        require(paused, "Pausable: not paused");
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @dev Same double-hash leaf as OpenZeppelin `StandardMerkleTree`:
    ///      `keccak256(bytes.concat(keccak256(abi.encode(account, amount, validFrom))))`.
    function _verifyAndMark(uint256 amount, uint256 validFrom, bytes32[] calldata merkleProof) internal {
        /// forge-lint: disable-next-line(block-timestamp)
        require(block.timestamp >= validFrom, "Stage not yet claimable");

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender, amount, validFrom))));

        require(!hasClaimed[leaf], "Stage already claimed");
        require(_verify(merkleProof, claimMerkleRoot, leaf), "Invalid Merkle proof");

        hasClaimed[leaf] = true;
    }

    /// @dev OpenZeppelin `MerkleProof.verify` (sorted pairs).
    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash == root;
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        if (a > b) (a, b) = (b, a);
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

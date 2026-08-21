// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Satset
/// @notice EIP-7702 rescue helper: a sponsor relays a signed claim/transfer so a
///         delegated EOA can move ERC-20 or native balances to a safe recipient.
contract Satset {

    /*//////////////////////////////////////////////////////////////
                          IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Address of this implementation; used to detect delegated vs contract context.
    address private immutable _SELF;

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Upper bound on tokens processed in a single `sweepERC20` call.
    uint256 public constant MAX_TOKENS = 50;

    string public constant NAME    = "Satset";
    string public constant VERSION = "1";

    bytes32 private constant NAME_HASH    = keccak256(bytes(NAME));
    bytes32 private constant VERSION_HASH = keccak256(bytes(VERSION));

    /*//////////////////////////////////////////////////////////////
                           STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-account, per-sponsor replay protection for EIP-712 signatures.
    mapping(address account => mapping(address sponsor => uint256)) public accountNonces;

    /*//////////////////////////////////////////////////////////////
                          EIP-712
    //////////////////////////////////////////////////////////////*/

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant CLAIM_TRANSFER_TYPEHASH = keccak256(
        "ClaimAndTransfer(address safeRecipient,address token,address claimTarget,bytes32 claimDataHash,address satset,address sponsor,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant CLAIM_TRANSFER_NATIVE_TYPEHASH = keccak256(
        "ClaimAndTransferNative(address safeRecipient,address claimTarget,bytes32 claimDataHash,address satset,address sponsor,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant TRANSFER_TOKEN_TYPEHASH = keccak256(
        "TransferToken(address safeRecipient,bytes32 tokensHash,address satset,address sponsor,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant TRANSFER_NATIVE_TYPEHASH = keccak256(
        "TransferNative(address safeRecipient,address satset,address sponsor,uint256 nonce,uint256 deadline)"
    );

    /*//////////////////////////////////////////////////////////////
                   ERC-7201 NAMESPACED STORAGE
    //////////////////////////////////////////////////////////////*/

    struct SatsetStorage {
        address owner;
        bool paused;
        mapping(address => bool) blocked;
    }

    /**
     * @dev keccak256(abi.encode(uint256(keccak256("erc7201:Satset.storage.v1")) - 1))
     *      & ~bytes32(uint256(0xff))
     */
    bytes32 private constant STORAGE_SLOT =
        0x140bd555879fc59b79e394342d698c0df822823092d151b71be076161c607d00;

    function _getStorage() private pure returns (SatsetStorage storage $) {
        bytes32 slot = STORAGE_SLOT;
        assembly { $.slot := slot }
    }

    /*//////////////////////////////////////////////////////////////
                           EVENTS
    //////////////////////////////////////////////////////////////*/

    event Rescued(
        address indexed account,
        address indexed safeRecipient,
        address indexed token,
        uint256 amount
    );
    event Paused(address indexed account);
    event Unpaused(address indexed account);
    event AccountBlocked(address indexed account);
    event AccountUnblocked(address indexed account);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /*//////////////////////////////////////////////////////////////
                           ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidRecipient();
    error InvalidToken();
    error InvalidClaimTarget();
    error SelfRecipient();
    error TooManyTokens();
    error InvalidSignature();
    error SignatureExpired();
    error ClaimFailed();
    error TransferFailed();
    error NoBalance();
    error ExecuteFailed(bytes reason);
    error Unauthorized();
    error ContractPaused();
    error AccountIsBlocked();
    error NotDelegatedToSatset();
    error Reentrancy();

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert InvalidRecipient();
        _SELF = address(this);
        SatsetStorage storage $ = _getStorage();
        $.owner = initialOwner;
    }

    /*//////////////////////////////////////////////////////////////
                         MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier nonReentrant() {
        bool entered;
        assembly { entered := tload(0) }
        if (entered) revert Reentrancy();
        assembly { tstore(0, 1) }
        _;
        assembly { tstore(0, 0) }
    }

    modifier onlyOwner() {
        if (msg.sender != _getStorage().owner) revert Unauthorized();
        _;
    }

    modifier onlySelf() {
        if (address(this) != _SELF) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (_getStorage().paused) revert ContractPaused();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function owner() public view returns (address) { return _getStorage().owner; }
    function paused() public view returns (bool) { return _getStorage().paused; }
    function blocked(address account) public view returns (bool) { return _getStorage().blocked[account]; }

    function nonceOf(address account, address sponsor) external view returns (uint256) {
        return accountNonces[account][sponsor];
    }

    /*//////////////////////////////////////////////////////////////
               TOKEN RECEIVER HOOKS (DELEGATED EOA)
    //////////////////////////////////////////////////////////////*/

    function onERC721Received(address, address, uint256, bytes calldata) external view returns (bytes4) {
        if (address(this) == _SELF) revert Unauthorized();
        return 0x150b7a02;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external view returns (bytes4) {
        if (address(this) == _SELF) revert Unauthorized();
        return 0xf23a6e61;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external view returns (bytes4) {
        if (address(this) == _SELF) revert Unauthorized();
        return 0xbc197c81;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (address(this) == _SELF) revert Unauthorized();
        if (_recover(hash, signature) == address(this)) return 0x1626ba7e;
        return 0xffffffff;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7
            || interfaceId == 0x150b7a02
            || interfaceId == 0x4e2312e0
            || interfaceId == 0x1626ba7e;
    }

    /*//////////////////////////////////////////////////////////////
                  RELAY ENTRY POINTS (SPONSOR)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Claims from `claimTarget`, then sends the full ERC-20 balance
     *         of `token` to `safeRecipient`. No fee is taken.
     */
    function recoverERC20(
        address account,
        address safeRecipient,
        address token,
        address claimTarget,
        bytes calldata claimData,
        uint256 deadline,
        bytes calldata signature
    ) external payable nonReentrant whenNotPaused {
        if (address(this) != _SELF) revert Unauthorized();
        if (safeRecipient == address(0)) revert InvalidRecipient();
        if (safeRecipient == account) revert SelfRecipient();
        if (token == address(0)) revert InvalidToken();
        if (claimTarget == address(0)) revert InvalidClaimTarget();
        /// forge-lint: disable-next-line(block-timestamp)
        if (deadline < block.timestamp) revert SignatureExpired();

        _verifyDelegation(account);
        if (_getStorage().blocked[account]) revert AccountIsBlocked();

        {
            uint256 nonce = accountNonces[account][msg.sender];
            bytes32 digest = keccak256(abi.encodePacked(
                "\x19\x01",
                _domainSeparator(account),
                keccak256(bytes.concat(
                    abi.encode(
                        CLAIM_TRANSFER_TYPEHASH,
                        safeRecipient,
                        token,
                        claimTarget,
                        keccak256(claimData)
                    ),
                    abi.encode(
                        _SELF,
                        msg.sender,
                        nonce,
                        deadline
                    )
                ))
            ));
            if (_recover(digest, signature) != account) revert InvalidSignature();
            accountNonces[account][msg.sender] = nonce + 1;
        }

        bytes memory payload = abi.encodeWithSelector(
            this.executeRecoverERC20.selector,
            safeRecipient, token, claimTarget, claimData
        );
        (bool success, bytes memory returndata) = account.call{value: msg.value}(payload);
        if (!success) _propagateRevert(returndata);
    }

    /**
     * @notice Claims from `claimTarget`, then sends the full native ETH balance
     *         to `safeRecipient`. No fee is taken.
     */
    function recoverNative(
        address account,
        address safeRecipient,
        address claimTarget,
        bytes calldata claimData,
        uint256 deadline,
        bytes calldata signature
    ) external payable nonReentrant whenNotPaused {
        if (address(this) != _SELF) revert Unauthorized();
        if (safeRecipient == address(0)) revert InvalidRecipient();
        if (safeRecipient == account) revert SelfRecipient();
        if (claimTarget == address(0)) revert InvalidClaimTarget();
        /// forge-lint: disable-next-line(block-timestamp)
        if (deadline < block.timestamp) revert SignatureExpired();

        _verifyDelegation(account);
        if (_getStorage().blocked[account]) revert AccountIsBlocked();

        {
            uint256 nonce = accountNonces[account][msg.sender];
            bytes32 digest = keccak256(abi.encodePacked(
                "\x19\x01",
                _domainSeparator(account),
                keccak256(bytes.concat(
                    abi.encode(
                        CLAIM_TRANSFER_NATIVE_TYPEHASH,
                        safeRecipient,
                        claimTarget,
                        keccak256(claimData)
                    ),
                    abi.encode(
                        _SELF,
                        msg.sender,
                        nonce,
                        deadline
                    )
                ))
            ));
            if (_recover(digest, signature) != account) revert InvalidSignature();
            accountNonces[account][msg.sender] = nonce + 1;
        }

        bytes memory payload = abi.encodeWithSelector(
            this.executeRecoverNative.selector,
            safeRecipient, claimTarget, claimData
        );
        (bool success, bytes memory returndata) = account.call{value: msg.value}(payload);
        if (!success) _propagateRevert(returndata);
    }

    /**
     * @notice Moves one or more ERC-20 balances already held by the EOA to
     *         `safeRecipient`. No claim step and no fee.
     */
    function sweepERC20(
        address account,
        address safeRecipient,
        address[] calldata tokens,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (address(this) != _SELF) revert Unauthorized();
        if (safeRecipient == address(0)) revert InvalidRecipient();
        if (safeRecipient == account) revert SelfRecipient();
        if (tokens.length == 0) revert InvalidToken();
        if (tokens.length > MAX_TOKENS) revert TooManyTokens();
        /// forge-lint: disable-next-line(block-timestamp)
        if (deadline < block.timestamp) revert SignatureExpired();

        _verifyDelegation(account);
        if (_getStorage().blocked[account]) revert AccountIsBlocked();

        {
            uint256 nonce = accountNonces[account][msg.sender];

            for (uint256 i = 0; i < tokens.length;) {
                if (tokens[i] == address(0)) revert InvalidToken();
                unchecked { ++i; }
            }

            bytes32 digest = keccak256(abi.encodePacked(
                "\x19\x01",
                _domainSeparator(account),
                keccak256(bytes.concat(
                    abi.encode(
                        TRANSFER_TOKEN_TYPEHASH,
                        safeRecipient,
                        keccak256(abi.encodePacked(tokens))
                    ),
                    abi.encode(
                        _SELF,
                        msg.sender,
                        nonce,
                        deadline
                    )
                ))
            ));
            if (_recover(digest, signature) != account) revert InvalidSignature();
            accountNonces[account][msg.sender] = nonce + 1;
        }

        bytes memory payload = abi.encodeWithSelector(
            this.executeSweepERC20.selector,
            safeRecipient, tokens
        );
        (bool success, bytes memory returndata) = account.call(payload);
        if (!success) _propagateRevert(returndata);
    }

    /**
     * @notice Moves the EOA's entire native ETH balance to `safeRecipient`.
     *         No fee is taken.
     */
    function sweepNative(
        address account,
        address safeRecipient,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (address(this) != _SELF) revert Unauthorized();
        if (safeRecipient == address(0)) revert InvalidRecipient();
        if (safeRecipient == account) revert SelfRecipient();
        /// forge-lint: disable-next-line(block-timestamp)
        if (deadline < block.timestamp) revert SignatureExpired();

        _verifyDelegation(account);
        if (_getStorage().blocked[account]) revert AccountIsBlocked();

        {
            uint256 nonce = accountNonces[account][msg.sender];
            bytes32 digest = keccak256(abi.encodePacked(
                "\x19\x01",
                _domainSeparator(account),
                keccak256(abi.encode(
                    TRANSFER_NATIVE_TYPEHASH,
                    safeRecipient,
                    _SELF,
                    msg.sender,
                    nonce,
                    deadline
                ))
            ));
            if (_recover(digest, signature) != account) revert InvalidSignature();
            accountNonces[account][msg.sender] = nonce + 1;
        }

        bytes memory payload = abi.encodeWithSelector(
            this.executeSweepNative.selector,
            safeRecipient
        );
        (bool success, bytes memory returndata) = account.call(payload);
        if (!success) _propagateRevert(returndata);
    }

    /*//////////////////////////////////////////////////////////////
              EXECUTE FUNCTIONS (DELEGATED EOA CONTEXT)
    //////////////////////////////////////////////////////////////*/

    function executeRecoverERC20(
        address safeRecipient,
        address token,
        address claimTarget,
        bytes calldata claimData
    ) external payable {
        if (msg.sender != _SELF) revert Unauthorized();

        (bool success,) = claimTarget.call{value: msg.value}(claimData);
        if (!success) revert ClaimFailed();

        uint256 amount = IERC20(token).balanceOf(address(this));
        if (amount == 0) revert NoBalance();
        _safeTransfer(token, safeRecipient, amount);
        emit Rescued(address(this), safeRecipient, token, amount);
    }

    function executeRecoverNative(
        address safeRecipient,
        address claimTarget,
        bytes calldata claimData
    ) external payable {
        if (msg.sender != _SELF) revert Unauthorized();

        (bool success,) = claimTarget.call{value: msg.value}(claimData);
        if (!success) revert ClaimFailed();

        uint256 amount = address(this).balance;
        if (amount == 0) revert NoBalance();
        (bool ok,) = safeRecipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Rescued(address(this), safeRecipient, address(0), amount);
    }

    function executeSweepERC20(
        address safeRecipient,
        address[] calldata tokens
    ) external {
        if (msg.sender != _SELF) revert Unauthorized();

        uint256 tokensTransferred = 0;
        for (uint256 i = 0; i < tokens.length;) {
            uint256 amount = IERC20(tokens[i]).balanceOf(address(this));
            if (amount > 0) {
                _safeTransfer(tokens[i], safeRecipient, amount);
                emit Rescued(address(this), safeRecipient, tokens[i], amount);
                unchecked { ++tokensTransferred; }
            }
            unchecked { ++i; }
        }

        if (tokensTransferred == 0) revert NoBalance();
    }

    function executeSweepNative(address safeRecipient) external {
        if (msg.sender != _SELF) revert Unauthorized();

        uint256 amount = address(this).balance;
        if (amount == 0) revert NoBalance();
        (bool ok,) = safeRecipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Rescued(address(this), safeRecipient, address(0), amount);
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN (CONTRACT CONTEXT)
    //////////////////////////////////////////////////////////////*/

    function changeOwner(address newOwner) external onlySelf onlyOwner whenNotPaused {
        if (newOwner == address(0)) revert InvalidRecipient();
        SatsetStorage storage $ = _getStorage();
        address previousOwner = $.owner;
        $.owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    function pause() external onlySelf onlyOwner whenNotPaused {
        _getStorage().paused = true;
        emit Paused(address(this));
    }

    function unpause() external onlySelf onlyOwner {
        SatsetStorage storage $ = _getStorage();
        if (!$.paused) return;
        $.paused = false;
        emit Unpaused(address(this));
    }

    function restrictAccount(address account) external onlySelf onlyOwner whenNotPaused {
        _getStorage().blocked[account] = true;
        emit AccountBlocked(account);
    }

    function allowAccount(address account) external onlySelf onlyOwner whenNotPaused {
        _getStorage().blocked[account] = false;
        emit AccountUnblocked(account);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Confirms `account` has EIP-7702 code that delegates to this implementation.
    function _verifyDelegation(address account) internal view {
        address self = _SELF;
        bool valid;
        assembly {
            let size := extcodesize(account)
            switch eq(size, 23)
            case 1 {
                let ptr := mload(0x40)
                extcodecopy(account, ptr, 0, 23)
                let first3 := shr(232, mload(ptr))
                let codeAddr := shr(96, mload(add(ptr, 3)))
                valid := and(eq(first3, 0xef0100), eq(codeAddr, self))
                mstore(0x40, add(ptr, 0x20))
            }
            default { valid := 0 }
        }
        if (!valid) revert NotDelegatedToSatset();
    }

    function _safeTransfer(address token, address to, uint256 amount) internal {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(ptr, 0x04), to)
            mstore(add(ptr, 0x24), amount)
            mstore(0x40, add(ptr, 0x60))
            let success := call(gas(), token, 0, ptr, 0x44, 0x00, 0x20)
            if iszero(and(success, or(iszero(returndatasize()), and(gt(returndatasize(), 31), eq(mload(0x00), 1))))) {
                mstore(0x00, 0x90b8ec18)
                revert(0x1c, 0x04)
            }
        }
    }

    function _domainSeparator(address account) internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            NAME_HASH,
            VERSION_HASH,
            block.chainid,
            account
        ));
    }

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(hash, v, r, s);
    }

    function _propagateRevert(bytes memory returndata) internal pure {
        if (returndata.length > 0) {
            assembly {
                revert(add(returndata, 0x20), mload(returndata))
            }
        }
        revert ExecuteFailed(returndata);
    }

    receive() external payable {
        if (address(this) == _SELF) revert Unauthorized();
    }

    fallback() external payable {
        if (address(this) == _SELF) revert Unauthorized();
    }
}

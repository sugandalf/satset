// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {Satset} from "../src/Satset.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockClaimableAirdrop} from "../src/mocks/MockClaimableAirdrop.sol";

/// @notice Integration tests for Satset `recoverERC20` against ClaimableAirdrop.
/// @dev EIP-7702 delegated EOA claims from the mock airdrop, then Satset sweeps
///      the tokens to a safe recipient.
contract SatsetIntegrationTest is Test {
    address internal account;
    uint256 internal accountPk;
    address internal safeRecipient = makeAddr("safeRecipient");
    address internal sponsor = makeAddr("sponsor");
    address internal distributor = makeAddr("distributor");

    uint256 internal constant CLAIM_AMOUNT = 10_000 ether;
    uint256 internal constant VALID_FROM = 1_700_000_000;
    uint256 internal constant SATSET_DEADLINE = VALID_FROM + 1 days;
    uint256 internal constant CLAIM_WINDOW_END = SATSET_DEADLINE + 365 days;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant CLAIM_TRANSFER_TYPEHASH = keccak256(
        "ClaimAndTransfer(address safeRecipient,address token,address claimTarget,bytes32 claimDataHash,address satset,address sponsor,uint256 nonce,uint256 deadline)"
    );
    bytes32 private constant NAME_HASH = keccak256(bytes("Satset"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    Satset public satset;
    MockERC20 public token;
    MockClaimableAirdrop public airdrop;

    address public foundation = makeAddr("foundation");
    address public satsetOwner = makeAddr("satsetOwner");

    bytes32 internal leafClaim;
    bytes32 internal leafOther;
    bytes32 internal leafStage2;
    bytes32 internal leafDummy;
    bytes32[] internal treeLeaves;
    bytes32 internal merkleRoot;

    uint256 internal constant STAGE2_AMOUNT = 2_500 ether;
    uint256 internal constant STAGE2_VALID_FROM = VALID_FROM + 1 days;

    event TokensClaimed(address indexed to, uint256 indexed amount);
    event Rescued(address indexed account, address indexed safeRecipient, address indexed token, uint256 amount);

    function setUp() public {
        (account, accountPk) = makeAddrAndKey("account");

        token = new MockERC20("Aligned Token", "ALIGN");
        airdrop = new MockClaimableAirdrop(foundation, address(token), distributor);
        satset = new Satset(satsetOwner);

        token.mint(distributor, 1_000_000 ether);
        vm.prank(distributor);
        token.approve(address(airdrop), type(uint256).max);

        _buildMerkleTree();

        vm.startPrank(foundation);
        airdrop.updateMerkleRoot(merkleRoot);
        airdrop.extendClaimPeriod(CLAIM_WINDOW_END);
        airdrop.unpause();
        vm.stopPrank();

        vm.warp(VALID_FROM + 1 hours);
        vm.deal(account, 1 ether);
        vm.deal(sponsor, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                              HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    function test_recoverERC20_claimAirdropToSafeRecipient() public {
        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claim.selector, CLAIM_AMOUNT, VALID_FROM, _proof(0));
        bytes memory signature = _signClaimAndTransfer(claimData, 0, SATSET_DEADLINE);

        vm.expectEmit(true, true, false, true, address(airdrop));
        emit TokensClaimed(account, CLAIM_AMOUNT);
        vm.expectEmit(true, true, true, true, account);
        emit Rescued(account, safeRecipient, address(token), CLAIM_AMOUNT);

        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature
        );

        assertEq(token.balanceOf(safeRecipient), CLAIM_AMOUNT);
        assertEq(token.balanceOf(account), 0);
        assertEq(token.balanceOf(distributor), 1_000_000 ether - CLAIM_AMOUNT);
        assertTrue(airdrop.hasClaimed(leafClaim));
        assertEq(satset.nonceOf(account, sponsor), 1);
    }

    function test_recoverERC20_claimBatchMultipleStages() public {
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = CLAIM_AMOUNT;
        amounts[1] = STAGE2_AMOUNT;

        uint256[] memory validFroms = new uint256[](2);
        validFroms[0] = VALID_FROM;
        validFroms[1] = STAGE2_VALID_FROM;

        bytes32[][] memory proofs = new bytes32[][](2);
        proofs[0] = _proof(0);
        proofs[1] = _proof(2);

        vm.warp(STAGE2_VALID_FROM + 1);

        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claimBatch.selector, amounts, validFroms, proofs);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory signature = _signClaimAndTransfer(claimData, 0, deadline);

        uint256 expected = CLAIM_AMOUNT + STAGE2_AMOUNT;

        vm.expectEmit(true, true, false, true, address(airdrop));
        emit TokensClaimed(account, expected);
        vm.expectEmit(true, true, true, true, account);
        emit Rescued(account, safeRecipient, address(token), expected);

        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        satset.recoverERC20(account, safeRecipient, address(token), address(airdrop), claimData, deadline, signature);

        assertEq(token.balanceOf(safeRecipient), expected);
        assertEq(token.balanceOf(account), 0);
        assertTrue(airdrop.hasClaimed(leafClaim));
        assertTrue(airdrop.hasClaimed(leafStage2));
    }

    function test_recoverERC20_sweepsPreexistingTokenBalance() public {
        uint256 extra = 123 ether;
        token.mint(account, extra);

        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claim.selector, CLAIM_AMOUNT, VALID_FROM, _proof(0));
        bytes memory signature = _signClaimAndTransfer(claimData, 0, SATSET_DEADLINE);

        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature
        );

        assertEq(token.balanceOf(safeRecipient), CLAIM_AMOUNT + extra);
        assertEq(token.balanceOf(account), 0);
    }

    /*//////////////////////////////////////////////////////////////
                           FAILURE CASES
    //////////////////////////////////////////////////////////////*/

    function test_recoverERC20_revertsOnInvalidMerkleProof() public {
        bytes32[] memory badProof = _proof(1); // sibling path for a different leaf
        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claim.selector, CLAIM_AMOUNT, VALID_FROM, badProof);
        bytes memory signature = _signClaimAndTransfer(claimData, 0, SATSET_DEADLINE);

        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        vm.expectRevert(Satset.ClaimFailed.selector);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature
        );
    }

    function test_recoverERC20_revertsWhenStageNotYetClaimable() public {
        vm.warp(VALID_FROM - 1);

        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claim.selector, CLAIM_AMOUNT, VALID_FROM, _proof(0));
        bytes memory signature = _signClaimAndTransfer(claimData, 0, SATSET_DEADLINE);

        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        vm.expectRevert(Satset.ClaimFailed.selector);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature
        );
    }

    function test_recoverERC20_revertsOnReplayClaim() public {
        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claim.selector, CLAIM_AMOUNT, VALID_FROM, _proof(0));
        bytes memory signature = _signClaimAndTransfer(claimData, 0, SATSET_DEADLINE);

        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature
        );

        bytes memory signature2 = _signClaimAndTransfer(claimData, 1, SATSET_DEADLINE);
        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        vm.expectRevert(Satset.ClaimFailed.selector);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature2
        );
    }

    function test_recoverERC20_revertsOnInvalidSatsetSignature() public {
        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claim.selector, CLAIM_AMOUNT, VALID_FROM, _proof(0));
        (, uint256 otherPk) = makeAddrAndKey("notAccount");
        bytes memory signature = _signWith(otherPk, claimData, 0, SATSET_DEADLINE);

        vm.signAndAttachDelegation(address(satset), accountPk);
        vm.prank(sponsor);
        vm.expectRevert(Satset.InvalidSignature.selector);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature
        );
    }

    function test_recoverERC20_revertsWhenNotDelegated() public {
        bytes memory claimData =
            abi.encodeWithSelector(MockClaimableAirdrop.claim.selector, CLAIM_AMOUNT, VALID_FROM, _proof(0));
        bytes memory signature = _signClaimAndTransfer(claimData, 0, SATSET_DEADLINE);

        vm.prank(sponsor);
        vm.expectRevert(Satset.NotDelegatedToSatset.selector);
        satset.recoverERC20(
            account, safeRecipient, address(token), address(airdrop), claimData, SATSET_DEADLINE, signature
        );
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    function _leaf(address claimant, uint256 amount, uint256 validFrom) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(claimant, amount, validFrom))));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32 value) {
        if (a > b) (a, b) = (b, a);
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }

    function _buildMerkleTree() internal {
        leafClaim = _leaf(account, CLAIM_AMOUNT, VALID_FROM);
        leafOther = _leaf(makeAddr("otherClaimant"), 1 ether, VALID_FROM);
        leafStage2 = _leaf(account, STAGE2_AMOUNT, STAGE2_VALID_FROM);
        leafDummy = _leaf(makeAddr("dummy"), 1, VALID_FROM);

        treeLeaves = new bytes32[](4);
        treeLeaves[0] = leafClaim;
        treeLeaves[1] = leafOther;
        treeLeaves[2] = leafStage2;
        treeLeaves[3] = leafDummy;

        bytes32 h01 = _hashPair(treeLeaves[0], treeLeaves[1]);
        bytes32 h23 = _hashPair(treeLeaves[2], treeLeaves[3]);
        merkleRoot = _hashPair(h01, h23);
    }

    function _proof(uint256 index) internal view returns (bytes32[] memory proof) {
        proof = new bytes32[](2);
        if (index < 2) {
            proof[0] = treeLeaves[index ^ 1];
            proof[1] = _hashPair(treeLeaves[2], treeLeaves[3]);
        } else {
            proof[0] = treeLeaves[index ^ 1];
            proof[1] = _hashPair(treeLeaves[0], treeLeaves[1]);
        }
    }

    function _domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, verifyingContract));
    }

    function _signClaimAndTransfer(bytes memory claimData, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        return _signWith(accountPk, claimData, nonce, deadline);
    }

    function _signWith(uint256 pk, bytes memory claimData, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            bytes.concat(
                abi.encode(
                    CLAIM_TRANSFER_TYPEHASH, safeRecipient, address(token), address(airdrop), keccak256(claimData)
                ),
                abi.encode(address(satset), sponsor, nonce, deadline)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(account), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}

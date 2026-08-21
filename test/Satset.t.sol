// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {Satset} from "../src/Satset.sol";

contract SatsetTest is Test {
    Satset public satset;
    address public owner = makeAddr("owner");

    bytes32 private constant EXPECTED_STORAGE_SLOT =
        0x140bd555879fc59b79e394342d698c0df822823092d151b71be076161c607d00;

    function setUp() public {
        satset = new Satset(owner);
    }

    function test_nameAndVersion() public view {
        assertEq(satset.NAME(), "Satset");
        assertEq(satset.VERSION(), "1");
        assertEq(satset.MAX_TOKENS(), 50);
    }

    function test_ownerStoredInErc7201Slot() public view {
        bytes32 computed = keccak256(abi.encode(uint256(keccak256("erc7201:Satset.storage.v1")) - 1))
            & ~bytes32(uint256(0xff));
        assertEq(computed, EXPECTED_STORAGE_SLOT);
        assertEq(satset.owner(), owner);
        assertEq(address(uint160(uint256(vm.load(address(satset), computed)))), owner);
    }

    function test_constructorRejectsZeroOwner() public {
        vm.expectRevert(Satset.InvalidRecipient.selector);
        new Satset(address(0));
    }

    function test_pauseAndUnpause() public {
        vm.prank(owner);
        satset.pause();
        assertTrue(satset.paused());

        vm.prank(owner);
        satset.unpause();
        assertFalse(satset.paused());
    }

    function test_transferOwnership() public {
        address next = makeAddr("nextOwner");
        vm.prank(owner);
        satset.changeOwner(next);
        assertEq(satset.owner(), next);
    }

    function test_blockAndUnblockAccount() public {
        address account = makeAddr("account");
        vm.prank(owner);
        satset.restrictAccount(account);
        assertTrue(satset.blocked(account));

        vm.prank(owner);
        satset.allowAccount(account);
        assertFalse(satset.blocked(account));
    }

    function test_executeOnImplementationRevertsUnauthorized() public {
        vm.expectRevert(Satset.Unauthorized.selector);
        satset.executeSweepNative(makeAddr("recipient"));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PhotoRegistry {
    struct Claim { address owner; uint256 timestamp; }
    mapping(bytes32 => Claim) public claims;

    event Anchored(bytes32 indexed fileHash, address indexed owner, uint256 timestamp);
    event Transferred(bytes32 indexed fileHash, address indexed from, address indexed to, uint256 timestamp);

    error AlreadyClaimed();
    error NotOwner();
    error InvalidRecipient();

    function anchor(bytes32 fileHash) external {
        if (claims[fileHash].owner != address(0)) revert AlreadyClaimed();
        claims[fileHash] = Claim(msg.sender, block.timestamp);
        emit Anchored(fileHash, msg.sender, block.timestamp);
    }

}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {OnchainCertification} from "./OnchainCertification.sol";

contract CertificationFactory {
    error UuidTaken();
    error InvalidName();

    mapping(uint256 uuid => bool) uuidTaken;
    address[] public certificationAddresses;

    event NewInstituionRegistered(string institutionName, uint256 instituionId);

    /**
     * @dev Factory to deploy instances of OnchainCertification
     * @param institutionName The institution that is gonna use the OnchainCertification Protocol
     * @param instituionId Unique Identifier Id for the Institution
     */
    function deployCertification(string memory institutionName, uint256 instituionId, address _admin)
        external
        returns (address certificationAddress)
    {
        if (uuidTaken[instituionId]) {
            revert UuidTaken();
        }

        if (bytes(institutionName).length == 0) {
            revert InvalidName();
        }

        bytes32 salt = keccak256(abi.encode(institutionName, instituionId, _admin, block.timestamp));

        bytes memory constructorArgs = abi.encode(institutionName, instituionId, _admin);

        bytes memory bytecode = abi.encodePacked(type(OnchainCertification).creationCode, constructorArgs);

        certificationAddress = Create2.deploy(0, salt, bytecode);

        uuidTaken[instituionId] = true;
        certificationAddresses.push(certificationAddress);

        emit NewInstituionRegistered(institutionName, instituionId);
    }

    /**
     * @dev Returns the total number of instituions
     * @return The total number of instituions
     */
    function getTotalInstituions() external view returns (uint256) {
        return certificationAddresses.length;
    }
}

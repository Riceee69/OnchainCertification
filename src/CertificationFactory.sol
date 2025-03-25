// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {OnchainCertification} from "./OnchainCertification.sol";

contract CertificationFactory {
    error UuidTaken();
    error InvalidName();

    mapping(uint256 uuid => bool) uuidTaken;
    address[] public certificationAddresses;

    event NewInstitutionRegistered(string institutionName, uint256 institutionId);

    /**
     * @dev Factory to deploy instances of OnchainCertification
     * @param institutionName The institution that is gonna use the OnchainCertification Protocol
     * @param institutionId Unique Identifier Id for the Institution
     */
    function deployCertification(string memory institutionName, uint256 institutionId, address _admin)
        external
        returns (address certificationAddress)
    {
        if (uuidTaken[institutionId]) {
            revert UuidTaken();
        }

        if (bytes(institutionName).length == 0) {
            revert InvalidName();
        }

        bytes32 salt = keccak256(abi.encode(institutionName, institutionId, _admin));

        bytes memory constructorArgs = abi.encode(institutionName, institutionId, _admin);

        bytes memory bytecode = abi.encodePacked(type(OnchainCertification).creationCode, constructorArgs);

        certificationAddress = Create2.deploy(0, salt, bytecode);

        uuidTaken[institutionId] = true;
        certificationAddresses.push(certificationAddress);

        emit NewInstitutionRegistered(institutionName, institutionId);
    }


    /**
     * @dev Returns the total number of institutions
     * @return The total number of institutions
     */
    function getTotalInstitutions() external view returns (uint256) {
        return certificationAddresses.length;
    }
}

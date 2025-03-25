// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {CertificationFactory} from "../src/CertificationFactory.sol";

contract DeployCertifiationFactory is Script {
    function run() public returns(address) {

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        CertificationFactory certificationFactory = new CertificationFactory();
        vm.stopBroadcast();

        return address(certificationFactory);
    }
}

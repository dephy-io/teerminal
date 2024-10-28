// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library CertLib {
    struct Cert {
        bytes prover;
        bytes provee;
        bytes derivation;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    function unpackCert(bytes calldata cert) public pure returns (Cert memory) {
        Cert memory c;
        // First Ensure the cert payload is 257 bytes
        require(cert.length == 257, "Invalid Cert Length");
        // First 64 bytes is the prover's address
        c.prover = cert[0:64];
        // Next 64 bytes is the provee's address
        c.provee = cert[64:128];
        // Next 64 bytes is the derivation
        c.derivation = cert[128:192];
        // Next 32 bytes is the r value
        c.r = abi.decode(cert[192:224], (bytes32));
        // Next 32 bytes is the s value
        c.s = abi.decode(cert[224:256], (bytes32));
        // Last byte is the v value
        c.v = uint8(cert[256]);
        return c;
    }


    function verifyCert(Cert memory c) public pure returns (bool) {
        bytes memory signingBody = abi.encodePacked(c.derivation, c.provee);
        bytes32 hash = keccak256(signingBody);
        // Call ecrecover with the hash, v, r, and s values
        address signer = ecrecover(hash, c.v, c.r, c.s);
        // Convert the prover bytes to an address by using the last 20 bytes of the prover bytes
        address prover = address(uint160(uint256(keccak256(c.prover))));
        // Ensure the signer is the prover
        return signer == prover;
    }

    function verifyCertChain(bytes calldata chain, bytes memory chainRoot) public pure returns (bytes memory cert) {
        // Ensure the chain's length is devisible by 257
        require(chain.length % 257 == 0, "Invalid Chain Length");
        Cert memory c;
        bytes memory prover = chainRoot;
        // Loop through the chain and verify each cert
        for (uint i = 0; i < chain.length; i += 257) {
            c = unpackCert(chain[i:i+257]);
            // Ensure the cert is valid
            require(verifyCert(c), "Invalid Cert");
            // Ensure the cert's prover is the same as the root
            require(keccak256(c.prover) == keccak256(prover), "Invalid Cert Derivation");
            // Update the root to the provee
            prover = c.provee;
        }
        return prover;
    }
}
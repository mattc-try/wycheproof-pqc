# Wycheproof-PQC

A comprehensive project for testing and analyzing post-quantum cryptography implementations, built on the foundation of Project Wycheproof's principles for cryptographic testing.

The project provides tools for:

1. Generating and parsing test vectors for post-quantum algorithms
2. Validating implementations against known answer tests
3. Testing interoperability between different implementations

## Project Structure

The project is organized into several key directories:

* **ideas/** : Contains conceptual documentation, including `falcon.md` with notes about the Falcon signature scheme.
* **liboqs/** : Integration with the Open Quantum Safe library, which provides:
  * Implementations of quantum-resistant cryptographic algorithms
  * A common API for post-quantum key encapsulation mechanisms (KEMs) and digital signature algorithms
  * Test harnesses and benchmarking tools
* **parsing-gen/** : Scripts for parsing and generating test vectors:
  * `script_falc.py` and `script_kyb.py` for handling Falcon and Kyber test vectors
  * `KAT_falc/` and `KAT_kyb/` directories containing Known Answer Test vectors
* **schemas/** : JSON schema definitions, including `falcon_sign_schema.json` for validating Falcon signature test vectors
* **tested-implementations/** : Directory for tested implementations of post-quantum algorithms
* **unit/** : Unit testing components
* **vect/:** KATs test for implementation interface
* **vectors/** : Test vector storage and organization

## Usage

Put your implementations needed in the tested implemnetations directory, on the respective directory falcon, mldsa or mlkem, here is a version with the implementations from PQClean this requires a bit of adaptation.

Once done make sure everything is linked with the naming and then run test.py, this script will compile what you need in the outputs/ directory, follow steps in the CLI

## Disclaimer

This software is provided for research and testing purposes.


# Wycheproof-PQC

A comprehensive project for testing and analyzing post-quantum cryptography implementations, built on the foundation of Project Wycheproof's principles for cryptographic testing.

The project provides tools for:

1. Generating and parsing test vectors for post-quantum algorithms
2. Validating implementations against known answer tests (KATs)
3. Testing interoperability between different implementations

## Project Structure

The project is organized into several key directories:

* **implementations/**: Contains header files and implementation directories
  * Header files: `falcon.h`, `mldsa.h`, `mlkem.h`
  * Implementation subdirectories: `falcon/`, `mldsa/`, `mlkem/`
* **parsing-gen/**: Scripts for parsing and generating test vectors
  * `script_falc.py` and `script_kyb.py` for handling Falcon and Kyber test vectors
  * `KAT_falc/` and `KAT_kyb/` directories containing Known Answer Test vectors
* **schemas/**: JSON schema definitions for validating test vectors
  * Examples: `falcon_sign_schema.json`, `falcon_verify_schema.json`, `mldsa_sign_schema.json`
* **tested-implementations/**: Directory for tested implementations of post-quantum algorithms
* **unit/**: Unit testing components for each algorithm
  * Test files: `falcon_test.c`, `mldsa_test.c`, `mlkem_test.c`
* **vect/**: Known Answer Test (KAT) tests for implementation interfaces
  * Test files: `v_falcon.c`, `v_mldsa.c`, `v_mlkem.c`
* **vectors/**: Test vector storage and organization

## Algorithms

The project currently supports the following post-quantum algorithms:

1. **ML-KEM** (Module Lattice Key Encapsulation Mechanism)

   * Parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024
   * Formerly known as Kyber
2. **ML-DSA** (Module Lattice Digital Signature Algorithm)

   * Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87
   * Formerly known as Dilithium
3. **Falcon** (Fast-Fourier Lattice-based Compact Signatures over NTRU)

   * Parameter sets: Falcon-512, Falcon-1024

## Usage

### Automated Testing with test.py

The easiest way to compile and run tests is using the provided `test.py` script:

```bash
python test.py
```

This script will:

1. Ask you to choose between unit tests, vector tests, or both
2. Ask which algorithm(s) to test
3. Compile the necessary files
4. Run the tests with appropriate parameters

### Manual Compilation and Testing

#### Compiling Unit Tests

Unit tests verify basic functionality of the PQC implementations:

```bash
# Create outputs directory if it doesn't exist
mkdir -p outputs

# Compile ML-KEM unit tests
gcc -o outputs/mlkem_test unit/mlkem_test.c implementations/mlkem/mlkem.c -I. -std=c99 -Wall

# Compile ML-DSA unit tests
gcc -o outputs/mldsa_test unit/mldsa_test.c implementations/mldsa/mldsa.c -I. -std=c99 -Wall

# Compile Falcon unit tests
gcc -o outputs/falcon_test unit/falcon_test.c implementations/falcon/falcon.c -I. -std=c99 -Wall
```


#### Compiling Vector Tests

Vector tests validate implementations against Known Answer Tests (KATs). These tests require the Jansson library for JSON parsing:

```
# Run ML-KEM vector tests
./outputs/v_mlkem vectors/kyber512_tests.json

# Run ML-DSA vector tests
./outputs/v_mldsa vectors/mldsa_44_draft_sign_test.json

# Run Falcon vector tests
./outputs/v_falcon vectors/falcon512_rsp_sign_kat.json
```

running vector tests choose the vector json file, this is automatic with all in the test.py implementation:

```
./outputs/v_mldsavectors/mldsa_44_draft_sign_test.json
```

## Implementing Your Own Versions

To test your own implementations:

1. Place your implementation files in the appropriate subdirectory under [implementations](vscode-file://vscode-app/Applications/Visual%20Studio%20Code%202.app/Contents/Resources/app/out/vs/code/electron-sandbox/workbench/workbench.html):
   * [falcon.c](vscode-file://vscode-app/Applications/Visual%20Studio%20Code%202.app/Contents/Resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)
   * [mldsa.c](vscode-file://vscode-app/Applications/Visual%20Studio%20Code%202.app/Contents/Resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)
   * [mlkem.c](vscode-file://vscode-app/Applications/Visual%20Studio%20Code%202.app/Contents/Resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)
2. Ensure your implementations conform to the API defined in the header files:
   * [falcon.h](vscode-file://vscode-app/Applications/Visual%20Studio%20Code%202.app/Contents/Resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)
   * [mldsa.h](vscode-file://vscode-app/Applications/Visual%20Studio%20Code%202.app/Contents/Resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)
   * [mlkem.h](vscode-file://vscode-app/Applications/Visual%20Studio%20Code%202.app/Contents/Resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)
3. Run the tests using the methods described above.

## Disclaimer

This software is provided for research and testing purposes only.

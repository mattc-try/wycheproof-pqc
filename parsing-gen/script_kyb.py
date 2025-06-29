import json
import os

def parse_nist_kat_file(content):
    """Parses NIST KAT-style files (.req or .rsp)"""
    test_cases = []
    current_case = {}
    
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.startswith('count ='):
            if current_case: 
                test_cases.append(current_case)
            current_case = {} 

        if '=' in line: 
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            current_case[key] = value
            
    if current_case: 
        test_cases.append(current_case)
    
    return test_cases

def generate_mlkem_test_group(keygen_cases, encaps_cases, param_set, source_files):
    """Generates JSON structure for ML-KEM test vectors"""
    kg_dec_tests = []
    encaps_tests = []
    
    # Process KeyGen and Decaps cases
    for i, case in enumerate(keygen_cases):
        kg_dec_tests.append({
            "tcId": i,
            "seed": case.get("seed", ""),
            "ek": case.get("pk", ""),
            "c": case.get("ct", ""),
            "K": case.get("ss", ""),
            "result": "valid"
        })
    
    # Process Encaps cases if available
    if encaps_cases:
        for i, case in enumerate(encaps_cases, start=len(keygen_cases)):
            encaps_tests.append({
                "tcId": i,
                "ek": case.get("pk", ""),
                "m": case.get("d", ""),
                "c": case.get("ct", ""),
                "K": case.get("ss", ""),
                "result": "valid"
            })
    
    source_info = {
        "method": "Generated from NIST KAT files",
        "filename": source_files
    }
    
    test_groups = [{
        "type": "MLKEMTest",
        "source": source_info,
        "parameterSet": param_set,
        "tests": kg_dec_tests
    }]
    
    if encaps_tests:
        test_groups.append({
            "type": "MLKEMEncapsTest",
            "source": source_info,
            "parameterSet": param_set,
            "tests": encaps_tests
        })
    
    return {
        "algorithm": "ML-KEM",
        "header": [
            f"Test vectors for {param_set} derived from NIST KAT files",
            f"Source: {source_files}"
        ],
        "notes": {
            "Valid": "All test cases are valid"
        },
        "numberOfTests": len(kg_dec_tests) + len(encaps_tests),
        "schema": "mlkem_test_schema.json",
        "testGroups": test_groups
    }

def main():
    variants = {
        "kyber512": {
            "rsp": "KAT_kyb/kyber512/PQCkemKAT_1632.rsp",
            "param_set": "ML-KEM-512"
        },
        "kyber512-90s": {
            "rsp": "KAT_kyb/kyber512-90s/PQCkemKAT_1632.rsp",
            "param_set": "ML-KEM-512"
        },
        "kyber768": {
            "rsp": "KAT_kyb/kyber768/PQCkemKAT_2400.rsp",
            "param_set": "ML-KEM-768"
        },
        "kyber768-90s": {
            "rsp": "KAT_kyb/kyber768-90s/PQCkemKAT_2400.rsp",
            "param_set": "ML-KEM-768"
        },
        "kyber1024": {
            "rsp": "KAT_kyb/kyber1024/PQCkemKAT_3168.rsp",
            "param_set": "ML-KEM-1024"
        },
        "kyber1024-90s": {
            "rsp": "KAT_kyb/kyber1024-90s/PQCkemKAT_3168.rsp",
            "param_set": "ML-KEM-1024"
        }
    }
    
    # Create output directory if it doesn't exist
    output_dir = "output_kyb"
    os.makedirs(output_dir, exist_ok=True)
    
    for variant, info in variants.items():
        rsp_file = info["rsp"]
        param_set = info["param_set"]
        
        if not os.path.exists(rsp_file):
            print(f"Error: {rsp_file} not found")
            continue
        
        try:
            # Parse response file
            with open(rsp_file, "r") as f:
                rsp_content = f.read()
            rsp_cases = parse_nist_kat_file(rsp_content)
            
            # Split into KeyGen and Encaps cases
            # Kyber KAT files typically have 100 KeyGen cases followed by 100 Encaps cases
            keygen_cases = rsp_cases[:100]
            encaps_cases = rsp_cases[100:] if len(rsp_cases) > 100 else []
            
            # Generate JSON structure
            json_output = generate_mlkem_test_group(
                keygen_cases,
                encaps_cases,
                param_set,
                rsp_file
            )
            
            # Save to file
            output_filename = f"{output_dir}/{variant}_tests.json"
            with open(output_filename, "w") as f:
                json.dump(json_output, f, indent=2)
            print(f"Successfully generated {output_filename}")
            
        except Exception as e:
            print(f"Error processing {variant}: {str(e)}")
            continue

if __name__ == "__main__":
    main()
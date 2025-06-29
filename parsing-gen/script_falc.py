import json
import os

def parse_nist_kat_file(content):
    """
    Parses NIST KAT-style files (.req or .rsp).
    Assumes 'count' starts a new test case block.
    """
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

def generate_falcon_sign_req_json(test_cases, algorithm_variant, generator_version="1.0"):
    """
    Generates JSON for Falcon signing requests from parsed .req file data.
    The 'privateKey' in the output JSON will be the 'seed' from the .req file.
    The 'sig' field will be empty, as it's meant to be generated.
    Schema path is relative to the output JSON file's location.
    """
    sign_groups = []
    for case in test_cases:
        sign_group = {
            "type": "FalconSign",
            "privateKey": case.get('seed', ''), 
            "tests": [{
                "tcId": int(case['count']),
                "comment": f"Test case {case['count']} for {algorithm_variant} signature generation. Seed: {case.get('seed', 'N/A')}",
                "msg": case.get('msg', ''),
                "sig": "",  
                "result": "valid", 
                "flags": ["RequiresSignatureGeneration"]
            }]
        }
        sign_groups.append(sign_group)
    
    return {
        "algorithm": algorithm_variant,
        "generatorVersion": generator_version,
        "header": [
            f"Test vectors for {algorithm_variant} signing, derived from a .req file.",
            "The 'privateKey' field contains the seed. The 'sig' field is initially empty."
        ],
        "notes": {
            "RequiresSignatureGeneration": {
                "bugType": "N/A",
                "description": "This test vector is for a signing operation; the signature needs to be generated using the provided message and private key (derived from seed)."
            }
        },
        "numberOfTests": sum(len(group["tests"]) for group in sign_groups),
        "schema": "../schemas/falcon_sign_schema.json", # Updated relative path
        "testGroups": sign_groups
    }

def generate_falcon_sign_kat_json(test_cases, algorithm_variant, generator_version="1.0"):
    """
    Generates JSON for Falcon signing Known Answer Tests (KATs) from parsed .rsp file data.
    Schema path is relative to the output JSON file's location.
    """
    sign_groups = []
    for case in test_cases:
        if not all(k in case for k in ['mlen', 'smlen', 'sm', 'sk', 'count', 'msg']):
            print(f"Warning: Skipping test case {case.get('count', 'N/A')} due to missing fields for sign KAT.")
            continue
            
        mlen = int(case['mlen'])
        smlen = int(case['smlen'])
        
        if smlen < mlen:
            print(f"Warning: Skipping test case {case['count']} due to invalid smlen ({smlen}) < mlen ({mlen}).")
            continue

        siglen_bytes = smlen - mlen
        sig_hex = case['sm'][:2 * siglen_bytes]
        
        sign_group = {
            "type": "FalconSign",
            "privateKey": case['sk'],
            "tests": [{
                "tcId": int(case['count']),
                "comment": f"KAT Sign Test case {case['count']} for {algorithm_variant}. Seed: {case.get('seed', 'N/A')}",
                "msg": case['msg'],
                "sig": sig_hex,
                "result": "valid", 
                "flags": ["ValidSignature"]
            }]
        }
        sign_groups.append(sign_group)
    
    return {
        "algorithm": algorithm_variant,
        "generatorVersion": generator_version,
        "header": [f"Known Answer Test vectors for {algorithm_variant} signing, derived from .rsp file."],
        "notes": {
            "ValidSignature": {
                "bugType": "N/A", 
                "description": "The test vector contains a known valid signature generated with the provided private key and message."
            }
        },
        "numberOfTests": sum(len(group["tests"]) for group in sign_groups),
        "schema": "../schemas/falcon_sign_schema.json", # Updated relative path
        "testGroups": sign_groups
    }

def generate_falcon_verify_kat_json(test_cases, algorithm_variant, generator_version="1.0"):
    """
    Generates JSON for Falcon verification Known Answer Tests (KATs) from parsed .rsp file data.
    Schema path is relative to the output JSON file's location.
    """
    verify_groups = []
    for case in test_cases:
        if not all(k in case for k in ['mlen', 'smlen', 'sm', 'pk', 'count', 'msg']):
            print(f"Warning: Skipping test case {case.get('count', 'N/A')} due to missing fields for verify KAT.")
            continue

        mlen = int(case['mlen'])
        smlen = int(case['smlen'])

        if smlen < mlen:
            print(f"Warning: Skipping test case {case['count']} due to invalid smlen ({smlen}) < mlen ({mlen}).")
            continue
            
        siglen_bytes = smlen - mlen
        sig_hex = case['sm'][:2 * siglen_bytes]
        
        verify_group = {
            "type": "FalconVerify",
            "publicKey": case['pk'],
            "tests": [{
                "tcId": int(case['count']),
                "comment": f"KAT Verify Test case {case['count']} for {algorithm_variant}. Seed: {case.get('seed', 'N/A')}",
                "msg": case['msg'],
                "sig": sig_hex,
                "result": "valid", 
                "flags": ["ValidSignature"]
            }]
        }
        verify_groups.append(verify_group)
    
    return {
        "algorithm": algorithm_variant,
        "generatorVersion": generator_version,
        "header": [f"Known Answer Test vectors for {algorithm_variant} verification, derived from .rsp file."],
        "notes": {
             "ValidSignature": {
                "bugType": "N/A",
                "description": "The test vector contains a known valid signature to be verified with the provided public key and message."
            }
        },
        "numberOfTests": sum(len(group["tests"]) for group in verify_groups),
        "schema": "../schemas/falcon_verify_schema.json", # Updated relative path
        "testGroups": verify_groups
    }

# --- Main execution logic ---
def main():
    # Assumes script is in KAT_falc/ and KAT files are also in KAT_falc/
    # Output JSONs will be written to KAT_falc/
    # Schema files are expected in ../schemas/ relative to output JSONs

    algorithms = {
        "Falcon-512": {"req": "KAT_falc/falcon512-KAT.req", "rsp": "KAT_falc/falcon512-KAT.rsp"},
        "Falcon-1024": {"req": "KAT_falc/falcon1024-KAT.req", "rsp": "KAT_falc/falcon1024-KAT.rsp"}
    }

    for algo_name, files in algorithms.items():
        req_file_name = files["req"]
        rsp_file_name = files["rsp"]
        
        # Process .req file
        try:
            if os.path.exists(req_file_name):
                with open(req_file_name, 'r') as f_req:
                    req_content = f_req.read()
                req_test_cases = parse_nist_kat_file(req_content)
                if req_test_cases:
                    sign_req_json_output = generate_falcon_sign_req_json(req_test_cases, algo_name)
                    output_filename_req = f"{algo_name.lower().replace('-', '')}_req_sign.json" # e.g., falcon512_req_sign.json
                    with open(output_filename_req, 'w') as f_json:
                        json.dump(sign_req_json_output, f_json, indent=2)
                    print(f"Generated {output_filename_req} from {req_file_name}")
                else:
                    print(f"No test cases found in {req_file_name}.")
            else:
                print(f"Warning: {req_file_name} not found. Skipping.")
        except Exception as e:
            print(f"An error occurred processing {req_file_name}: {e}")

        # Process .rsp file
        try:
            if os.path.exists(rsp_file_name):
                with open(rsp_file_name, 'r') as f_rsp:
                    rsp_content = f_rsp.read()
                rsp_test_cases = parse_nist_kat_file(rsp_content)
                if rsp_test_cases:
                    # Generate Falcon Sign KAT JSON from .rsp
                    sign_kat_json_output = generate_falcon_sign_kat_json(rsp_test_cases, algo_name)
                    output_filename_sign_kat = f"{algo_name.lower().replace('-', '')}_rsp_sign_kat.json"
                    with open(output_filename_sign_kat, 'w') as f_json:
                        json.dump(sign_kat_json_output, f_json, indent=2)
                    print(f"Generated {output_filename_sign_kat} from {rsp_file_name}")

                    # Generate Falcon Verify KAT JSON from .rsp
                    verify_kat_json_output = generate_falcon_verify_kat_json(rsp_test_cases, algo_name)
                    output_filename_verify_kat = f"{algo_name.lower().replace('-', '')}_rsp_verify_kat.json"
                    with open(output_filename_verify_kat, 'w') as f_json:
                        json.dump(verify_kat_json_output, f_json, indent=2)
                    print(f"Generated {output_filename_verify_kat} from {rsp_file_name}")
                else:
                    print(f"No test cases found in {rsp_file_name}.")
            else:
                print(f"Warning: {rsp_file_name} not found. Skipping.")
        except Exception as e:
            print(f"An error occurred processing {rsp_file_name}: {e}")

if __name__ == '__main__':
    main()
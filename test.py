import subprocess
import sys
import glob
import os # Import os module for path joining

print("Welcome to Wycheproof PQC.")
print("First, choose test type:")
print("1. Unit tests")
print("2. Vector tests with KATs")
print("3. Both")

test_type = input("Choice (1-3): ")

print("Select test:")
print("1. Falcon")
print("2. MLKEM")
print("3. MLDSA")
print("4. All")

choice = input("Choose a test to compile and run (1-4): ")

# Ensure outputs directory exists
os.makedirs("outputs", exist_ok=True)

# --- Define test configurations ---
# Each entry will be a list of dictionaries.
# Each dictionary represents a single compilation/run target.
# 'compile_cmd': The GCC command to compile.
# 'run_cmd_prefix': The executable path.
# 'kat_patterns': (Optional) A list of glob patterns for KAT files (for vector tests).

unit_tests_config = {
    "1": [
        {"compile_cmd": "gcc -o outputs/falcon_test unit/falcon_test.c implementations/falcon/falcon.c -I. -std=c99 -Wall",
         "run_cmd_prefix": "./outputs/falcon_test"}
    ],
    "2": [
        {"compile_cmd": "gcc -o outputs/mlkem_test unit/mlkem_test.c implementations/mlkem/mlkem.c -I. -std=c99 -Wall",
         "run_cmd_prefix": "./outputs/mlkem_test"}
    ],
    "3": [
        {"compile_cmd": "gcc -o outputs/mldsa_test unit/mldsa_test.c implementations/mldsa/mldsa.c -I. -std=c99 -Wall",
         "run_cmd_prefix": "./outputs/mldsa_test"}
    ],
    "4": [] # Will be populated by combining 1, 2, 3
}
unit_tests_config["4"].extend(unit_tests_config["1"])
unit_tests_config["4"].extend(unit_tests_config["2"])
unit_tests_config["4"].extend(unit_tests_config["3"])


vector_tests_config = {
    "1": [
        {"compile_cmd": "gcc -o outputs/v_falcon vect/v_falcon.c implementations/falcon/falcon.c -I. -std=c99 -Wall -I/opt/homebrew/include -L/opt/homebrew/lib -ljansson",
         "run_cmd_prefix": "./outputs/v_falcon",
         "kat_patterns": ["vectors/falcon*_rsp_sign_kat.json", "vectors/falcon*_rsp_verify_kat.json"]}
    ],
    "2": [
        {"compile_cmd": "gcc -o outputs/v_mlkem vect/v_mlkem.c implementations/mlkem/mlkem.c -I. -std=c99 -Wall -I/opt/homebrew/include -L/opt/homebrew/lib -ljansson",
         "run_cmd_prefix": "./outputs/v_mlkem",
         "kat_patterns": ["vectors/kyber*_tests.json", "vectors/kyber*-90s_tests.json"]}
    ],
    "3": [
        {"compile_cmd": "gcc -o outputs/v_mldsa vect/v_mldsa.c implementations/mldsa/mldsa.c -I. -std=c99 -Wall -I/opt/homebrew/include -L/opt/homebrew/lib -ljansson",
         "run_cmd_prefix": "./outputs/v_mldsa",
         "kat_patterns": ["vectors/mldsa_*_draft_sign_test.json", "vectors/mldsa_*_draft_verify_test.json",
                          "vectors/mldsa_*_round3_sign_test.json", "vectors/mldsa_*_round3_verify_test.json"]}
    ],
    "4": [] # Will be populated by combining 1, 2, 3
}
vector_tests_config["4"].extend(vector_tests_config["1"])
vector_tests_config["4"].extend(vector_tests_config["2"])
vector_tests_config["4"].extend(vector_tests_config["3"])


selected_configs = []

if test_type == "1":
    selected_configs = unit_tests_config.get(choice)
elif test_type == "2":
    selected_configs = vector_tests_config.get(choice)
elif test_type == "3":
    selected_configs = unit_tests_config.get(choice, []) + vector_tests_config.get(choice, [])
else:
    print("Invalid test type choice.")
    sys.exit(1)

if not selected_configs:
    print("Invalid test selection.")
    sys.exit(1)

# --- Compilation Phase ---
print("\n--- Compiling Tests ---")
compilation_successful = True
for config in selected_configs:
    compile_cmd = config['compile_cmd']
    print(f"Compiling: {compile_cmd}")
    try:
        subprocess.run(compile_cmd, shell=True, check=True)
        print("Compilation successful.")
    except subprocess.CalledProcessError:
        print(f"Compilation failed for: {compile_cmd}")
        compilation_successful = False
        break # Stop if any compilation fails

if not compilation_successful:
    print("Aborting test run due to compilation failures.")
    sys.exit(1)

# --- Running Phase ---
def run_tests(configs_to_run):
    print("\n--- Running Tests ---")
    for config in configs_to_run:
        run_prefix = config['run_cmd_prefix']
        
        if 'kat_patterns' in config and config['kat_patterns']:
            # This is a vector test, needs KAT files
            print(f"Running vector tests for {os.path.basename(run_prefix)}...")
            found_kats = []
            for pattern in config['kat_patterns']:
                found_kats.extend(glob.glob(pattern))
            
            if not found_kats:
                print(f"  No KAT files found for {os.path.basename(run_prefix)} with patterns: {config['kat_patterns']}")
                continue # Skip to next config if no KATs found
            
            for kat_file in sorted(found_kats): # Sort for consistent order
                cmd_to_run = f"{run_prefix} {kat_file}"
                print(f"  Executing: {cmd_to_run}")
                try:
                    # Capture output to prevent interleaving with other prints
                    result = subprocess.run(cmd_to_run, shell=True, check=False, capture_output=True, text=True)
                    print(result.stdout.strip()) # Print stdout, remove trailing newline if any
                    if result.stderr:
                        print(f"Stderr for {os.path.basename(kat_file)}:\n{result.stderr.strip()}")
                    
                    if result.returncode != 0:
                        print(f"  Test FAILED for {os.path.basename(kat_file)}. Exit code: {result.returncode}")
                    else:
                        print(f"  Test PASSED for {os.path.basename(kat_file)}.")
                except FileNotFoundError:
                    print(f"Error: Executable not found: {run_prefix}")
                except Exception as e:
                    print(f"An error occurred while running {cmd_to_run}: {e}")
        else:
            # This is a unit test, no KAT files needed
            cmd_to_run = run_prefix
            print(f"Running unit test: {os.path.basename(cmd_to_run)}")
            try:
                result = subprocess.run(cmd_to_run, shell=True, check=False, capture_output=True, text=True)
                print(result.stdout.strip())
                if result.stderr:
                    print(f"Stderr for {os.path.basename(cmd_to_run)}:\n{result.stderr.strip()}")
                
                if result.returncode != 0:
                    print(f"  Test FAILED. Exit code: {result.returncode}")
                else:
                    print(f"  Test PASSED.")
            except FileNotFoundError:
                print(f"Error: Executable not found: {run_prefix}")
            except Exception as e:
                print(f"An error occurred while running {cmd_to_run}: {e}")

# Call the run function after successful compilation
run_tests(selected_configs)

print("\n--- Test Run Complete ---")

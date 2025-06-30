import subprocess
import sys

print("Welcome to Wycheproof PQC.")
print("The current implemented tests are:")
print("1. Falcon")
print("2. MLKEM")
print("3. MLDSA")
print("4. All")

choice = input("Choose a test to compile and run (1-4): ")

# Map choice to files
test_map = {
    "1": ["gcc -o outputs/falcon_test unit/falcon_test.c implementations/falcon/falcon.c -I. -std=c99 -Wall"],
    "2": ["gcc -o outputs/mlkem_test unit/mlkem_test.c implementations/mlkem/mlkem.c -I. -std=c99 -Wall"],
    "3": ["gcc -o outputs/mldsa_test unit/mldsa_test.c implementations/mldsa/mldsa.c -I. -std=c99 -Wall"],
    "4": [
        "gcc -o outputs/falcon_test unit/falcon_test.c implementations/falcon/falcon.c -I. -std=c99 -Wall",
        "gcc -o outputs/mlkem_test unit/mlkem_test.c implementations/mlkem/mlkem.c -I. -std=c99 -Wall",
        "gcc -o outputs/mldsa_test unit/mldsa_test.c implementations/mldsa/mldsa.c -I. -std=c99 -Wall"
    ]
}

cmds = test_map.get(choice)

if not cmds:
    print("Invalid choice.")
    sys.exit(1)

for cmd in cmds:
    print("Compiling:", cmd)
    try:
        subprocess.run(cmd, shell=True, check=True)
        print("Compilation successful.")
    except subprocess.CalledProcessError:
        print("Compilation failed.")

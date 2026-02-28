import os
import subprocess
import sys

def run_test(path):
    cmd = ["forge", "test", "--match-path", path, "--via-ir"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

def mutate_and_test(file_path, test_path, mutations):
    with open(file_path, 'r') as f:
        original_content = f.read()
    
    print(f"Running mutations on {os.path.basename(file_path)}")
    print(f"Test file: {os.path.basename(test_path)}")
    
    results = []

    for i, (old, new) in enumerate(mutations):
        print(f"Testing Mutant {i+1}: {old} -> {new}")
        if old not in original_content:
            print(f"Skipping mutant {i+1}, target not found.")
            continue
            
        mutated_content = original_content.replace(old, new, 1)
        with open(file_path, 'w') as f:
            f.write(mutated_content)
        
        try:
            passed = run_test(test_path)
            if passed:
                print(f"DANGER: Mutant {i+1} SURVIVED!")
                results.append(f"Mutant {i+1}: SURVIVED")
            else:
                print(f"SUCCESS: Mutant {i+1} KILLED.")
                results.append(f"Mutant {i+1}: KILLED")
        except Exception as e:
            print(f"Error running test: {e}")
        finally:
            with open(file_path, 'w') as f:
                f.write(original_content)
    
    print("\nMutation Results:")
    for res in results:
        print(res)

if __name__ == "__main__":
    file_to_mutate = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "contracts", "primitives", "ZKBoundStateLocks.sol")
    test_to_run = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "test", "security", "ZKLockDoSProtection.t.sol")
    
    mutations = [
        # 1. Weaken bond requirement
        ("if (msg.value < MIN_BOND_AMOUNT)", "if (msg.value < MIN_BOND_AMOUNT - 1)"),
        # 2. Weaken challenger stake requirement
        ("if (msg.value < MIN_CHALLENGER_STAKE)", "if (msg.value < MIN_CHALLENGER_STAKE - 1)"),
        # 3. Disable dispute period check (finalize anytime)
        ("if (block.timestamp < optimistic.finalizeAfter)", "if (false)"),
        # 4. Disable double dispute check
        ("if (optimistic.disputed)", "if (false)"),
        # 5. Break challenge success logic (always fail challenge)
        ("if (!_verifyProof(lock, evidence))", "if (false)"),
        # 6. Break conflict proof logic (always succeed)
        ("if (evidence.newStateCommitment != optimistic.newStateCommitment)", "if (true)"),
    ]
    
    mutate_and_test(file_to_mutate, test_to_run, mutations)

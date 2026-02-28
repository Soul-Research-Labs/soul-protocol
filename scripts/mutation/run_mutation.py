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
            else:
                print(f"SUCCESS: Mutant {i+1} KILLED.")
        finally:
            with open(file_path, 'w') as f:
                f.write(original_content)

if __name__ == "__main__":
    file_to_mutate = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "contracts", "security", "SecurityModule.sol")
    test_to_run = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "test", "security", "SecurityModuleMutation.t.sol")
    
    mutations = [
        ("block.timestamp > lastActionTime[msg.sender] + rateLimitWindow", "block.timestamp >= lastActionTime[msg.sender] + rateLimitWindow"),
        ("actionCount[msg.sender] >= maxActionsPerWindow", "actionCount[msg.sender] > maxActionsPerWindow"),
        ("lastHourlyVolume > volumeThreshold", "lastHourlyVolume >= volumeThreshold"),
        ("circuitBreakerTripped = true;", "// circuitBreakerTripped = true;"),
        ("block.timestamp > lastHourTimestamp + 1 hours", "block.timestamp >= lastHourTimestamp + 1 hours"),
    ]
    
    mutate_and_test(file_to_mutate, test_to_run, mutations)

#!/usr/bin/env python3
"""
Auto NatSpec Documentation Generator for Zaseon

Automatically adds missing NatSpec documentation to Solidity contracts.
Adds @title, @author, @notice to contracts and @notice, @param, @return to functions.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple, Optional

# Directories to exclude
EXCLUDES = ['mocks', 'test', 'interfaces', 'verifiers/generated', 'coverage-stubs']

AUTHOR = "Zaseon Team"


def strip_comments(content: str) -> str:
    """Strip comments, preserving offsets by replacing with spaces."""
    result = list(content)
    i = 0
    while i < len(content) - 1:
        if content[i] == '/' and content[i + 1] == '/':
            j = i
            while j < len(content) and content[j] != '\n':
                result[j] = ' '
                j += 1
            i = j
        elif content[i] == '/' and content[i + 1] == '*':
            j = i + 2
            while j < len(content) - 1:
                if content[j] == '*' and content[j + 1] == '/':
                    j += 2
                    break
                j += 1
            else:
                j = len(content)
            for k in range(i, j):
                if content[k] != '\n':
                    result[k] = ' '
            i = j
        elif content[i] == '"':
            i += 1
            while i < len(content) and content[i] != '"':
                if content[i] == '\\':
                    i += 1
                i += 1
            i += 1
        else:
            i += 1
    return ''.join(result)


def find_matching_paren(content: str, start: int) -> int:
    """Find matching closing paren."""
    count = 1
    i = start + 1
    while i < len(content) and count > 0:
        if content[i] == '(':
            count += 1
        elif content[i] == ')':
            count -= 1
        i += 1
    return i - 1


def has_natspec_before(content: str, position: int) -> dict:
    """Check for NatSpec comments before a position in the original content."""
    search_start = max(0, position - 8000)
    block = content[search_start:position]

    result = {
        'has_notice': False,
        'has_dev': False,
        'has_title': False,
        'has_author': False,
        'param_names': [],
        'has_return': False,
    }

    last_comment = None
    for match in re.finditer(r'/\*\*[\s\S]*?\*/', block):
        last_comment = match

    if not last_comment:
        return result

    after_comment = block[last_comment.end():]
    if after_comment.strip():
        return result

    comment_text = last_comment.group()
    result['has_notice'] = '@notice' in comment_text
    result['has_dev'] = '@dev' in comment_text
    result['has_title'] = '@title' in comment_text
    result['has_author'] = '@author' in comment_text
    result['param_names'] = re.findall(r'@param\s+(\w+)', comment_text)
    result['has_return'] = '@return' in comment_text

    return result


def get_indent(content: str, position: int) -> str:
    """Get the indentation of the line at the given position."""
    line_start = content.rfind('\n', 0, position)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1
    indent = ''
    for ch in content[line_start:position]:
        if ch in (' ', '\t'):
            indent += ch
        else:
            break
    return indent


def generate_contract_name_desc(name: str) -> str:
    """Generate a human-readable description from a contract name."""
    # Split CamelCase into words
    words = re.sub(r'([A-Z])', r' \1', name).strip().split()
    # Handle common suffixes
    desc = ' '.join(words)
    return desc


def parse_param_names(content: str, paren_start: int) -> List[str]:
    """Parse parameter names from a function signature."""
    paren_end = find_matching_paren(content, paren_start)
    params_str = content[paren_start + 1:paren_end].strip()
    if not params_str:
        return []

    names = []
    for param in params_str.split(','):
        param = param.strip()
        if not param:
            continue
        # Parameter format: type [memory|storage|calldata] name
        # Or: type name
        parts = param.split()
        if len(parts) >= 2:
            # Last word is the name (unless it's memory/storage/calldata with no name)
            last = parts[-1]
            if last in ('memory', 'storage', 'calldata'):
                # No explicit name; skip unnamed parameters
                continue
            else:
                names.append(last)
        elif len(parts) == 1:
            # Just a type, no name — skip unnamed parameters
            continue
    return names


def parse_return_count(content: str, after_paren_end: int) -> int:
    """Count return values from the function signature."""
    after = content[after_paren_end:after_paren_end + 500]
    # Stop at opening brace or semicolon to avoid matching next function
    for stop_char in ('{', ';'):
        pos = after.find(stop_char)
        if pos >= 0:
            after = after[:pos]
    returns_match = re.search(r'returns\s*\(([^)]+)\)', after)
    if not returns_match:
        return 0
    returns_str = returns_match.group(1)
    return len([r for r in returns_str.split(',') if r.strip()])


def parse_return_names(content: str, after_paren_end: int) -> List[str]:
    """Parse return variable names from the function signature."""
    after = content[after_paren_end:after_paren_end + 500]
    # Stop at opening brace or semicolon to avoid matching next function
    for stop_char in ('{', ';'):
        pos = after.find(stop_char)
        if pos >= 0:
            after = after[:pos]
    returns_match = re.search(r'returns\s*\(([^)]+)\)', after)
    if not returns_match:
        return []
    returns_str = returns_match.group(1)
    names = []
    for ret in returns_str.split(','):
        ret = ret.strip()
        if not ret:
            continue
        parts = ret.split()
        if len(parts) >= 2:
            last = parts[-1]
            if last in ('memory', 'storage', 'calldata'):
                names.append('')
            else:
                names.append(last)
        else:
            names.append('')
    return names


def get_visibility(content: str, paren_end: int) -> str:
    """Get function visibility."""
    after = content[paren_end:paren_end + 200]
    if 'external' in after:
        return 'external'
    elif 'public' in after:
        return 'public'
    elif 'private' in after:
        return 'private'
    return 'internal'


def generate_func_notice(name: str) -> str:
    """Generate a reasonable @notice from function name."""
    # Split camelCase
    words = re.sub(r'([A-Z])', r' \1', name).strip().split()
    if not words:
        return name

    # Common verb patterns
    first = words[0].lower()
    rest = ' '.join(w.lower() for w in words[1:])

    if first == 'get' and rest:
        return f"Returns the {rest}"
    elif first == 'set' and rest:
        return f"Sets the {rest}"
    elif first == 'is' and rest:
        return f"Checks if {rest}"
    elif first == 'has' and rest:
        return f"Checks if has {rest}"
    elif first in ('update', 'register', 'remove', 'add', 'create',
                    'delete', 'pause', 'unpause', 'initialize', 'execute',
                    'verify', 'validate', 'process', 'submit', 'cancel',
                    'claim', 'revoke', 'grant', 'transfer', 'approve',
                    'deposit', 'withdraw', 'lock', 'unlock', 'emit',
                    'compute', 'calculate', 'check', 'enable', 'disable',
                    'configure', 'resolve', 'aggregate', 'batch', 'relay',
                    'propagate', 'migrate', 'rotate', 'escalate', 'slash',
                    'stake', 'unstake', 'swap', 'bridge', 'finalize',
                    'initiate', 'complete', 'recover', 'reset', 'request',
                    'respond', 'trigger', 'notify', 'report', 'renounce'):
        verb = first[0].upper() + first[1:]
        if rest:
            return f"{verb}s {rest}"
        else:
            return f"{verb}s the operation"
    elif first == 'on' and rest:
        return f"Callback handler for {rest}"
    elif first == '_':
        return f"Internal helper for {name}"
    else:
        desc = ' '.join(w.lower() for w in words)
        return desc[0].upper() + desc[1:] if desc else name


def generate_param_desc(param_name: str, func_name: str = '') -> str:
    """Generate a parameter description."""
    # Common parameter name patterns
    descs = {
        'amount': 'The amount to process',
        'value': 'The value to set',
        'recipient': 'The recipient address',
        'to': 'The destination address',
        'from': 'The source address',
        'sender': 'The sender address',
        'owner': 'The owner address',
        'account': 'The account address',
        'addr': 'The target address',
        'address_': 'The target address',
        'token': 'The token address',
        'tokenId': 'The token identifier',
        'chainId': 'The chain identifier',
        'destChain': 'The destination chain ID',
        'srcChain': 'The source chain ID',
        'destChainId': 'The destination chain identifier',
        'sourceChainId': 'The source chain identifier',
        'targetChainId': 'The target chain identifier',
        'proof': 'The ZK proof data',
        'proofData': 'The proof data bytes',
        'nullifier': 'The nullifier hash',
        'nullifierHash': 'The nullifier hash value',
        'commitment': 'The cryptographic commitment',
        'root': 'The Merkle root',
        'merkleRoot': 'The Merkle tree root',
        'data': 'The calldata payload',
        'payload': 'The message payload',
        'message': 'The message data',
        'messageId': 'The message identifier',
        'lockId': 'The lock identifier',
        'stateHash': 'The state hash',
        'deadline': 'The deadline timestamp',
        'timeout': 'The timeout duration',
        'nonce': 'The nonce value',
        'salt': 'The random salt',
        'secret': 'The secret value',
        'index': 'The index in the collection',
        'key': 'The lookup key',
        'id': 'The unique identifier',
        'operator': 'The operator address',
        'relayer': 'The relayer address',
        'relayerAddress': 'The relayer address',
        'fee': 'The fee amount',
        'feeAmount': 'The fee amount',
        'threshold': 'The threshold value',
        'minAmount': 'The minimum amount',
        'maxAmount': 'The maximum amount',
        'enabled': 'Whether the feature is enabled',
        'active': 'Whether the feature is active',
        'paused': 'Whether the contract is paused',
        'status': 'The status value',
        'role': 'The access control role',
        'adapter': 'The bridge adapter address',
        'bridge': 'The bridge contract address',
        'verifier': 'The verifier contract address',
        'implementation': 'The implementation address',
        'newImplementation': 'The new implementation address',
        'selector': 'The function selector',
        'signature': 'The cryptographic signature',
        'domain': 'The domain identifier',
        'domainId': 'The domain identifier',
        'commitment_': 'The cryptographic commitment',
        'container': 'The container data',
        'containerId': 'The container identifier',
        'circuitId': 'The circuit identifier',
        'score': 'The score value',
        'weight': 'The weight value',
        'duration': 'The duration in seconds',
        'limit': 'The limit value',
        'count': 'The count value',
        'level': 'The level value',
        'policy': 'The policy data',
        'policyId': 'The policy identifier',
        'version': 'The version number',
        'metadata': 'The metadata bytes',
        'reason': 'The reason string',
        'description': 'The description string',
        'spender': 'The spender address',
        'approved': 'The approval status',
    }

    if param_name in descs:
        return descs[param_name]

    # Try partial matches
    lower = param_name.lower()
    if 'hash' in lower:
        return f"The {param_name} hash value"
    if 'address' in lower or 'addr' in lower:
        return f"The {param_name} address"
    if 'amount' in lower:
        return f"The {param_name} amount"
    if 'count' in lower:
        return f"The {param_name} count"
    if 'id' in lower and lower != 'id':
        return f"The {param_name} identifier"
    if 'time' in lower or 'stamp' in lower:
        return f"The {param_name} timestamp"
    if 'flag' in lower or lower.startswith('is') or lower.startswith('has'):
        return f"Whether {param_name}"
    if 'new' in lower:
        return f"The new {param_name[3:] if lower.startswith('new') else param_name} value"
    if 'max' in lower or 'min' in lower:
        return f"The {param_name} bound"

    # Generic description from camelCase
    words = re.sub(r'([A-Z])', r' \1', param_name).strip().lower()
    return f"The {words}"


def generate_return_desc(name: str, index: int) -> str:
    """Generate a return value description."""
    if name:
        words = re.sub(r'([A-Z])', r' \1', name).strip().lower()
        return f"The {words}"
    if index == 0:
        return "The result value"
    return f"The result value at index {index}"


def process_file(file_path: Path, dry_run: bool = False) -> Tuple[int, int]:
    """
    Process a single Solidity file, adding missing NatSpec.
    Returns (contracts_fixed, functions_fixed).
    """
    content = file_path.read_text()
    stripped = strip_comments(content)

    # Collect all insertions as (position, text_to_insert)
    insertions: List[Tuple[int, str]] = []

    # --- Contract-level NatSpec ---
    contract_match = re.search(
        r'\b(contract|interface|library)\s+([A-Z]\w*)',
        stripped
    )
    if not contract_match:
        return (0, 0)

    contract_name = contract_match.group(2)
    contract_type = contract_match.group(1)
    contract_pos = contract_match.start()
    contract_docs = has_natspec_before(content, contract_pos)
    contracts_fixed = 0

    if not contract_docs['has_title'] or not contract_docs['has_notice']:
        indent = get_indent(content, contract_pos)
        desc = generate_contract_name_desc(contract_name)

        # Build the NatSpec block
        lines = []
        lines.append(f"{indent}/**")
        if not contract_docs['has_title']:
            lines.append(f"{indent} * @title {contract_name}")
        if not contract_docs['has_author']:
            lines.append(f"{indent} * @author {AUTHOR}")
        if not contract_docs['has_notice']:
            lines.append(f"{indent} * @notice {desc} {contract_type}")
        lines.append(f"{indent} */")

        # If there IS an existing NatSpec but it's missing some tags, we need
        # to add tags to the existing block instead of creating a new one
        if contract_docs['has_notice'] or contract_docs['has_title']:
            # There's an existing block; find it and add missing tags
            search_start = max(0, contract_pos - 3000)
            block = content[search_start:contract_pos]
            last_comment = None
            for m in re.finditer(r'/\*\*[\s\S]*?\*/', block):
                last_comment = m
            if last_comment:
                # Insert missing tags before the closing */
                abs_end = search_start + last_comment.end()
                close_pos = content.rfind('*/', search_start + last_comment.start(), abs_end) 
                if close_pos >= 0:
                    insert_lines = []
                    # Detect indent inside comment
                    comment_indent = indent + " "
                    if not contract_docs['has_title']:
                        insert_lines.append(f"{comment_indent}* @title {contract_name}\n")
                    if not contract_docs['has_author']:
                        insert_lines.append(f"{comment_indent}* @author {AUTHOR}\n")
                    if not contract_docs['has_notice']:
                        insert_lines.append(f"{comment_indent}* @notice {desc} {contract_type}\n")
                    if insert_lines:
                        insertions.append((close_pos, ''.join(insert_lines) + indent + " "))
                        contracts_fixed = 1
        else:
            # No existing NatSpec at all
            natspec = '\n'.join(lines) + '\n'
            insertions.append((contract_pos, natspec))
            contracts_fixed = 1

    # --- Function-level NatSpec ---
    functions_fixed = 0
    for match in re.finditer(r'\bfunction\s+(\w+)\s*\(', stripped):
        func_start = match.start()
        name = match.group(1)

        # Get visibility from stripped source
        paren_start = stripped.find('(', func_start)
        paren_end = find_matching_paren(stripped, paren_start)
        vis = get_visibility(stripped, paren_end)

        if vis not in ('external', 'public'):
            continue
        if name in ('supportsInterface', '_authorizeUpgrade'):
            continue

        func_docs = has_natspec_before(content, func_start)
        param_names = parse_param_names(stripped, paren_start)
        ret_count = parse_return_count(stripped, paren_end)
        ret_names = parse_return_names(stripped, paren_end)

        needs_notice = not func_docs['has_notice']
        # Check which params are missing
        existing_params = set(func_docs['param_names'])
        missing_params = [p for p in param_names if p not in existing_params]
        needs_return = ret_count > 0 and not func_docs['has_return']

        if not needs_notice and not missing_params and not needs_return:
            continue

        indent = get_indent(content, func_start)

        # If there's already a NatSpec block, add missing tags to it
        if func_docs['has_notice'] or func_docs['param_names'] or func_docs['has_return']:
            # Find existing block
            search_start = max(0, func_start - 3000)
            block = content[search_start:func_start]
            last_comment = None
            for m in re.finditer(r'/\*\*[\s\S]*?\*/', block):
                last_comment = m
            if last_comment:
                abs_end = search_start + last_comment.end()
                close_pos = content.rfind('*/', search_start + last_comment.start(), abs_end)
                if close_pos >= 0:
                    insert_lines = []
                    comment_indent = indent + " "
                    if needs_notice:
                        notice = generate_func_notice(name)
                        insert_lines.append(f"{comment_indent}* @notice {notice}\n")
                    for pname in missing_params:
                        pdesc = generate_param_desc(pname, name)
                        insert_lines.append(f"{comment_indent}* @param {pname} {pdesc}\n")
                    if needs_return:
                        for idx, rname in enumerate(ret_names):
                            rdesc = generate_return_desc(rname, idx)
                            insert_lines.append(f"{comment_indent}* @return {rname + ' ' if rname else ''}{rdesc}\n")
                    if insert_lines:
                        insertions.append((close_pos, ''.join(insert_lines) + indent + " "))
                        functions_fixed += 1
        else:
            # No existing NatSpec — create fresh block
            notice = generate_func_notice(name)
            lines = []
            lines.append(f"{indent}/**")
            lines.append(f"{indent} * @notice {notice}")
            for pname in param_names:
                pdesc = generate_param_desc(pname, name)
                lines.append(f"{indent} * @param {pname} {pdesc}")
            for idx in range(ret_count):
                rname = ret_names[idx] if idx < len(ret_names) else ''
                rdesc = generate_return_desc(rname, idx)
                if rname:
                    lines.append(f"{indent} * @return {rname} {rdesc}")
                else:
                    lines.append(f"{indent} * @return {rdesc}")
            lines.append(f"{indent} */")
            natspec = '\n'.join(lines) + '\n'
            insertions.append((func_start, natspec))
            functions_fixed += 1

    if not insertions or dry_run:
        return (contracts_fixed, functions_fixed)

    # Apply insertions in reverse order to preserve positions
    insertions.sort(key=lambda x: x[0], reverse=True)
    for pos, text in insertions:
        content = content[:pos] + text + content[pos:]

    file_path.write_text(content)
    return (contracts_fixed, functions_fixed)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Auto-generate NatSpec documentation')
    parser.add_argument('--path', default='contracts', help='Path to contracts')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be changed')
    parser.add_argument('--file', type=str, help='Process a single file')
    args = parser.parse_args()

    if args.file:
        fp = Path(args.file)
        c, f = process_file(fp, args.dry_run)
        print(f"{'[DRY RUN] ' if args.dry_run else ''}{fp}: {c} contract docs, {f} function docs added")
        return

    contracts_path = Path(args.path)
    sol_files = list(contracts_path.rglob("*.sol"))
    sol_files = [f for f in sol_files if not any(excl in str(f) for excl in EXCLUDES)]

    total_c = 0
    total_f = 0
    for sol_file in sorted(sol_files):
        c, f = process_file(sol_file, args.dry_run)
        if c > 0 or f > 0:
            prefix = '[DRY RUN] ' if args.dry_run else ''
            print(f"{prefix}{sol_file}: {c} contract docs, {f} function docs")
            total_c += c
            total_f += f

    print(f"\n{'[DRY RUN] ' if args.dry_run else ''}Total: {total_c} contracts, {total_f} functions documented")


if __name__ == "__main__":
    main()

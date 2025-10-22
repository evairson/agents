### Write code for the new module here and import it from agent.py.

rulesMetta = """

(:= (vulnerability "SolcVersion") (recommendation "Use the latest stable Solidity compiler (>=0.8.26) to avoid known vulnerabilities and bugs."))

(:= (vulnerability "Reentrancy") (recommendation "Use the Checks-Effects-Interactions pattern or ReentrancyGuard; update state before external calls."))

(:= (vulnerability "UncheckedCall") (recommendation "Always check the return value of low-level calls using require(success)."))

(:= (vulnerability "UncheckedSend") (recommendation "Use call() and check the result instead of send(); or use transfer() for automatic revert."))

(:= (vulnerability "IntegerOverflow") (recommendation "Use Solidity ^0.8.0 or SafeMath to prevent arithmetic overflows and underflows."))

(:= (vulnerability "Underflow") (recommendation "Use Solidity ^0.8.0 or SafeMath; validate arithmetic inputs before subtraction."))

(:= (vulnerability "TxOrigin") (recommendation "Do not use tx.origin for authentication; use msg.sender instead."))

(:= (vulnerability "TimestampDependency") (recommendation "Avoid using block.timestamp for randomness or critical logic; use block.number or secure oracles."))

(:= (vulnerability "UncheckedLowLevelCall") (recommendation "Always check the success boolean of low-level calls; wrap with require(success)."))

(:= (vulnerability "DelegateCallToUntrusted") (recommendation "Never delegatecall untrusted addresses; limit to trusted implementation contracts."))

(:= (vulnerability "Selfdestruct") (recommendation "Avoid unprotected selfdestruct(); restrict to owner-only or remove entirely."))

(:= (vulnerability "UninitializedStorage") (recommendation "Initialize storage variables explicitly before use to avoid default zero or garbage values."))

(:= (vulnerability "UninitializedLocalVariable") (recommendation "Always initialize local variables before use."))

(:= (vulnerability "UnprotectedUpgrade") (recommendation "Protect upgrade functions with proper access control (e.g., onlyOwner)."))

(:= (vulnerability "UnprotectedWrite") (recommendation "Restrict access to critical state-modifying functions with modifiers or ACLs."))

(:= (vulnerability "ControlledDelegateCall") (recommendation "Validate delegatecall targets; prevent arbitrary address injection."))

(:= (vulnerability "LowLevelCallInLoop") (recommendation "Avoid making external calls in unbounded loops; batch or limit iterations."))

(:= (vulnerability "CostlyLoop") (recommendation "Avoid loops with unbounded iterations or heavy computation to prevent gas exhaustion."))

(:= (vulnerability "DenialOfService") (recommendation "Avoid external calls or storage writes in unbounded loops that can block execution."))

(:= (vulnerability "HardcodedAddress") (recommendation "Avoid hardcoded addresses; use configurable constants or constructor parameters."))

(:= (vulnerability "UnboundedWrite") (recommendation "Restrict or cap writes to arrays or mappings to avoid DoS through unbounded storage growth."))

(:= (vulnerability "MissingZeroAddressCheck") (recommendation "Ensure that critical addresses are not zero; add require(address != 0) checks."))

(:= (vulnerability "MissingEvent") (recommendation "Emit events for critical state changes to aid monitoring and transparency."))

(:= (vulnerability "ArbitrarySendETH") (recommendation "Restrict who can withdraw or send ETH; validate recipients and permissions."))

(:= (vulnerability "ArbitrarySendERC20") (recommendation "Restrict and validate ERC20 transfers initiated by the contract; avoid arbitrary recipients."))

(:= (vulnerability "InsecureRandomness") (recommendation "Do not use blockhash or block.timestamp as random sources; use secure randomness or oracles."))

(:= (vulnerability "UnrestrictedEtherWithdrawal") (recommendation "Protect withdrawal functions with onlyOwner or require statements."))

(:= (vulnerability "Visibility") (recommendation "Explicitly declare function visibility (public/private/internal/external)."))

(:= (vulnerability "UnnecessaryPublicFunction") (recommendation "Restrict visibility for functions not intended to be called externally."))

(:= (vulnerability "ShadowedVariable") (recommendation "Avoid shadowing state variables or parameters; use distinct names."))

(:= (vulnerability "ShadowedStateVariable") (recommendation "Rename or restructure contracts to avoid shadowing parent contract state variables."))

(:= (vulnerability "MultipleConstructors") (recommendation "Use only one constructor with the 'constructor' keyword to avoid ambiguity."))

(:= (vulnerability "IncorrectConstructorName") (recommendation "Rename functions with the same name as the contract to 'constructor' (modern syntax)."))

(:= (vulnerability "ReentrancyNoEth") (recommendation "Even if no ETH is sent, reorder state changes before external calls or use ReentrancyGuard."))

(:= (vulnerability "ReentrancyEth") (recommendation "Protect payable functions with ReentrancyGuard; update state before transferring ETH."))

(:= (vulnerability "ReentrancyEvents") (recommendation "Reentrancy can occur via event emission triggering fallback logic; use safe patterns."))

(:= (vulnerability "PublicMappingNested") (recommendation "Avoid public nested mappings exposing private data; use controlled getter functions."))

(:= (vulnerability "ArrayByReference") (recommendation "Do not expose storage arrays directly; return copies in memory to prevent modification."))

(:= (vulnerability "EncodePackedCollision") (recommendation "Avoid abi.encodePacked() with multiple dynamic types; use abi.encode() instead."))

(:= (vulnerability "NameReused") (recommendation "Ensure unique contract and function names to avoid confusion and deployment issues."))

(:= (vulnerability "ProtectedVariables") (recommendation "Use proper visibility modifiers (private/internal) for critical state variables."))

(:= (vulnerability "IncorrectERC20") (recommendation "Follow ERC20 standard strictly; use SafeERC20 wrappers for non-standard tokens."))

(:= (vulnerability "ERC20ApproveRaceCondition") (recommendation "Implement the safe approval pattern: set allowance to 0 before changing to new value."))

(:= (vulnerability "MissingReentrancyGuard") (recommendation "Add nonReentrant modifier or ReentrancyGuard to vulnerable functions."))

(:= (vulnerability "DelegateCallToUninitialized") (recommendation "Initialize logic contracts before use; protect initialize functions."))
"""

CHECK_TO_VULN = {
    # ---- Reentrancy ----
    "reentrancy-eth": "ReentrancyEth",
    "reentrancy-no-eth": "ReentrancyNoEth",
    "reentrancy-events": "ReentrancyEvents",
    "missing-reentrancy-guard": "MissingReentrancyGuard",

    # ---- Low-level calls ----
    "unchecked-low-level-call": "UncheckedLowLevelCall",
    "unchecked-send": "UncheckedSend",
    "unchecked-call": "UncheckedCall",
    "low-level-call-in-loop": "LowLevelCallInLoop",

    # ---- Arithmetic ----
    "integer-overflow": "IntegerOverflow",
    "integer-underflow": "Underflow",

    # ---- tx.origin ----
    "tx-origin": "TxOrigin",

    # ---- Time dependency ----
    "timestamp-dependency": "TimestampDependency",
    "block-timestamp": "TimestampDependency",

    # ---- Delegatecall ----
    "delegatecall-to-untrusted": "DelegateCallToUntrusted",
    "controlled-delegatecall": "ControlledDelegateCall",
    "delegatecall-to-uninitialized": "DelegateCallToUninitialized",

    # ---- Selfdestruct ----
    "unprotected-selfdestruct": "Selfdestruct",
    "selfdestruct": "Selfdestruct",

    # ---- Initialization ----
    "uninitialized-storage": "UninitializedStorage",
    "uninitialized-local": "UninitializedLocalVariable",

    # ---- Upgrades & Writes ----
    "unprotected-upgrade": "UnprotectedUpgrade",
    "unprotected-write": "UnprotectedWrite",
    "unbounded-write": "UnboundedWrite",

    # ---- Loops / Gas ----
    "costly-loop": "CostlyLoop",
    "dos-with-unbounded-operation": "DenialOfService",
    "denial-of-service": "DenialOfService",

    # ---- Addresses ----
    "hardcoded-address": "HardcodedAddress",
    "missing-zero-address-check": "MissingZeroAddressCheck",

    # ---- Events ----
    "missing-event": "MissingEvent",

    # ---- ETH & ERC20 ----
    "arbitrary-send-eth": "ArbitrarySendETH",
    "arbitrary-send-erc20": "ArbitrarySendERC20",
    "unrestricted-ether-withdrawal": "UnrestrictedEtherWithdrawal",
    "erc20-approve-race-condition": "ERC20ApproveRaceCondition",
    "incorrect-erc20-interface": "IncorrectERC20",

    # ---- Randomness ----
    "insecure-randomness": "InsecureRandomness",

    # ---- Visibility ----
    "visibility": "Visibility",
    "unnecessary-public-function": "UnnecessaryPublicFunction",

    # ---- Variables ----
    "shadowed-variable": "ShadowedVariable",
    "shadowed-state-variable": "ShadowedStateVariable",
    "protected-variables": "ProtectedVariables",

    # ---- Constructors ----
    "multiple-constructors": "MultipleConstructors",
    "incorrect-constructor-name": "IncorrectConstructorName",

    # ---- Mappings ----
    "public-mapping-nested": "PublicMappingNested",

    # ---- Arrays ----
    "array-by-reference": "ArrayByReference",

    # ---- Encoding ----
    "encode-packed-collision": "EncodePackedCollision",

    # ---- Naming ----
    "name-reused": "NameReused",

    # ---- Compiler version ----
    "solc-version": "SolcVersion",  # ajoute cette clé à ton rules.metta
    "solc-version-pragmas": "SolcVersion",

    # ---- Misc ----
    "missing-event": "MissingEvent",
    "hardcoded-address": "HardcodedAddress",
}
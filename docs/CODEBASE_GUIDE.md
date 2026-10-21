# TPM 2.0 Fuzzer Codebase Guide & Reference

> **Welcome to the TPM 2.0 Fuzzer codebase.** This document provides an exhaustive, module-by-module and file-by-file walkthrough of the entire project, explains the TPM 2.0 commands tested by the framework, details how the custom session authorization and serialization layers work, and includes an interactive "Grill Me" technical examination section.

---

## 1. System Overview & Architecture

### What is This Project?
This project is a coverage-guided fuzzing framework built with **LLVM Clang (`libFuzzer`)** targeting **TPM 2.0** implementations (primarily the official **TCG TPM 2.0 Reference Implementation**, with modular support for backends like `libtpms`).

### The Dual-Mode Fuzzing Strategy
TPMs have two distinct attack surfaces:
1. **Low-Level Wire Parsers:** Buffer parsing, length checks, endianness translation, malformed TLV (type-length-value) packets.
2. **High-Level Cryptographic & State Logic:** Multi-step protocols (e.g., Auth Sessions, Primary Object creation -> child key derivation -> RSA decryption, PCR policy enforcement, NV index allocation).

To target both surfaces, the framework provides two fuzzing binaries and one reproduction tool:

```
                                  ┌───────────────────────────┐
                                  │      libFuzzer Engine      │
                                  └─────────────┬─────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     │                                                     │
         ┌───────────▼───────────┐                             ┌───────────▼───────────┐
         │   Byte Fuzzer Target  │                             │  Proto Fuzzer Target  │
         │   (`src/fuzzer.cc`)   │                             │(`src/proto-fuzzer.cc`)│
         └───────────┬───────────┘                             └───────────┬───────────┘
                     │                                                     │
         ┌───────────▼───────────┐                             ┌───────────▼───────────┐
         │     `byte_parser`     │                             │ `libprotobuf-mutator` │
         │ Splits buffer into    │                             │ Field-aware mutations │
         │ discrete TPM packets  │                             └───────────┬───────────┘
         └───────────┬───────────┘                                         │
                     │                                         ┌───────────▼───────────┐
                     │                                         │ `proto_postprocessors`│
                     │                                         │ & `proto_normalization│
                     │                                         └───────────┬───────────┘
                     │                                                     │
                     │                                         ┌───────────▼───────────┐
                     │                                         │  `proto_conversion`   │
                     │                                         │   (TSS2-MU wire bytes)│
                     │                                         └───────────┬───────────┘
                     │                                                     │
                     │                                         ┌───────────▼───────────┐
                     │                                         │  `session_auth` (HMAC)│
                     │                                         │ Computes valid nonces │
                     │                                         │ & HMAC auth digests   │
                     │                                         └───────────┬───────────┘
                     │                                                     │
                     └──────────────────────────┬──────────────────────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │     `tpm_wrapper`     │
                                    │ TCG Reference Platform│
                                    └───────────┬───────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │ TPM 2.0 Reference Core│
                                    └───────────────────────┘
```

---

## 2. Directory Structure & File Map

| Path | Purpose |
| :--- | :--- |
| `src/fuzzer.cc` | Entry point for raw, unstructured byte-level fuzzing. |
| `src/proto-fuzzer.cc` | Entry point for structure-aware protobuf fuzzing. |
| `src/tester.cc` | Standalone executable for debugging/reproducing test cases from disk. |
| `src/harness/tpm_wrapper.c` | Platform adapter for the TCG TPM reference implementation. |
| `include/harness/tpm_wrapper.h` | C interface to TPM startup, execution, shutdown, and manufacturing. |
| `src/harness/session_auth.cc` | Reactive HMAC session authorization engine and Name tracking. |
| `include/harness/session_auth.h` | Interface for bootstrapping, patching, and updating TPM sessions. |
| `include/harness/command_attributes.h`| Bitmasks and flags describing handle counts and session attributes. |
| `src/harness/proto_conversion.cc` | Serializes Protobuf objects into TPM 2.0 wire format using `tss2_mu`. |
| `include/harness/proto_conversion.h` | Declarations for command and data structure marshaling functions. |
| `src/harness/proto_normalization.cc` | Normalizes generated messages to valid tags, algorithms, and handles. |
| `include/harness/proto_normalization.h`| Declarations for command-specific normalization routines. |
| `src/harness/proto_postprocessors.cc` | Hooks `libprotobuf-mutator` to run normalization after mutation. |
| `include/harness/proto_postprocessors.h`| Registration hook `RegisterPostProcessors()`. |
| `src/parser/byte_parser.cc` | Splits raw byte stream into individual TPM commands based on packet length. |
| `include/parser/byte_parser.h` | Header for `parseCommands()`. |
| `include/proto/` | Protobuf definitions for TPM commands, constants, and data structures. |
| `tools/seed-generation/` | Python generator (`uv` based) producing seed corpus files. |
| `scripts/run-fuzzer.sh` | Main orchestration script for building and running fuzz targets. |
| `scripts/test-seed.sh` | Helper script to run an individual seed file against `Tester`. |
| `scripts/generate-seeds.sh` | Helper script to run Python seed generation tools. |
| `scripts/track-coverage` | Collects LLVM profile data and outputs coverage summaries. |
| `example/wrapper.cc` | Demonstrates plugging in an alternative TPM backend (`libtpms`). |

---

## 3. Deep Dive: Modules and Key Files

### A. Raw Byte Fuzzer: `src/fuzzer.cc` & `src/parser/byte_parser.cc`

#### 1. End-to-End Execution Flow

```text
  ┌─────────────────────────────────────────────────────────────┐
  │ Seed Corpus on Disk (Initial Valid Command Sequences)       │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ libFuzzer Mutation Engine                                   │
  │ • Mutates bytes across the flat buffer (bit flips, inserts) │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (passes raw Data, Size)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ LLVMFuzzerTestOneInput() (src/fuzzer.cc)                    │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ parseCommands() (src/parser/byte_parser.cc)                 │
  │ • Scans flat buffer using offset + length headers           │
  │ • Slices buffer into std::vector<std::vector<uint8_t>>      │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ TPM Hardware State Initialization                           │
  │ • TPMManufactureIfNeeded() -> TPMStartup() -> TPM2_Startup  │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Sequential One-by-One Dispatch Loop                         │
  │   for (auto& cmd : commands) {                              │
  │     TPMSendCommand(locality, request, &response);           │
  │   }                                                         │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Teardown & State Reset                                      │
  │ • SendTPM2ShutdownCommand() -> TPMShutdown()                │
  └─────────────────────────────────────────────────────────────┘
```

#### 2. Why Byte Parsing & Offset Slicing Exist
* **Single Flat Buffer Constraint:** LibFuzzer only operates on a single flat byte array (`const uint8_t* Data, size_t Size`). It has no concept of C++ structures or lists of commands.
* **TPM is a Stateful Machine:** Testing deep logic requires sequences of commands (e.g. `TPM2_CreatePrimary` $\rightarrow$ `TPM2_Create` $\rightarrow$ `TPM2_Load`). Therefore, multiple commands must be packed contiguously into that single flat buffer.
* **No Batched Wire Header:** Every single TPM command strictly requires its own standard 10-byte wire header (`tag` [2B], `length` [4B], `commandCode` [4B]). There is no single shared header for a sequence.
* **Offset Unpacking Logic (`byte_parser.cc`):**
  1. Starts at `offset = 0` and reads the 10-byte header.
  2. Extracts the 4-byte big-endian `length` using `ntohl()`.
  3. Verifies bounds (`length >= 10` and `offset + length <= size`).
  4. Slices `[offset, offset + length)` into an individual command vector:
     ```cpp
     commands.emplace_back(data + offset, data + offset + length);
     ```
  5. Advances `offset += length` and repeats until the buffer is fully unpacked.

#### 3. Dispatch & TPM Interaction
* The TPM reference core processes one transaction at a time.
* `fuzzer.cc` loops over each sliced command vector and sends it sequentially via `TPMSendCommand()` (`_plat__RunCommand()`).
* The TPM consumes the command, updates its internal state (transient object slots, PCRs, NVRAM), and returns a response before the next command in the chain is dispatched.

#### 4. Mutation & Corpus Lifecycle
* **Mutation Timing:** In the raw byte fuzzer, mutations happen **before** `LLVMFuzzerTestOneInput()` is called. LibFuzzer mutates the raw flat byte array.
* **No Post-Slicing Modification:** The sliced buffers are sent to the TPM **as-is without modifying any bits** (unlike `proto-fuzzer.cc`, which performs cryptographic HMAC patching via `SessionAuthPatchCommand`).
* **Seeds vs. Corpus:**
  * **Seeds (`seeds/bytearray/`):** Pre-crafted valid command sequences ensuring the fuzzer starts with valid syntax.
  * **Dynamic Corpus:** When a mutated buffer triggers new code paths/branches in `vendor/TPM`, LibFuzzer automatically saves that mutated flat file into the corpus directory.
  * **Inspection (`src/tester.cc`):** Standalone reproduction tool that takes a single corpus file from disk, runs it through `parseCommands()`, dispatches each command sequentially, and prints hex/binary dumps of commands and TPM responses.

### B. Structure-Aware Fuzzer: `src/proto-fuzzer.cc`

#### 1. End-to-End Execution Flow

```text
  ┌─────────────────────────────────────────────────────────────┐
  │ Protobuf Seed Corpus (seeds/proto/)                         │
  │ • Valid initial sequences generated by tools/seed-generation│
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (parsed into in-memory protobuf objects)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ libprotobuf-mutator (THE MUTATION STAGE)                    │
  │ • Mutates typed fields (integers, enums, attribute bits)    │
  │ • Mutates sequences (add, delete, reorder TPM commands)    │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (mutated C++ message tree)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Post-Processors & Normalization (proto_postprocessors.cc)   │
  │ • PostProcessorRegistration hooks fire automatically        │
  │ • Normalizes tags, clamps illegal enums, fixes parent keys  │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (normalized sequence object)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ DEFINE_PROTO_FUZZER(const tpm::TPMCommandSequence& seq)     │
  │ • Boots TPM, iterates over each command in seq.commands()   │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Wire Marshaling (proto_conversion.cc via tss2_mu)           │
  │ • Converts Protobuf C++ object into TPM 2.0 big-endian wire │
  │ • Dynamically calculates parameter sizes and wire lengths   │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (raw wire bytes)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Reactive HMAC Session Patching (session_auth.cc)            │
  │ • SessionAuthPatchCommand(): computes real cpHash & nonces  │
  │ • Calculates valid SHA-256 HMAC and patches auth area       │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (cryptographically valid wire packet)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ TPM Reference Execution (TPMSendCommand -> _plat__RunCommand│
  └──────────────────────────────┬──────────────────────────────┘
                                 │ (raw response wire bytes)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Dynamic Response Feedback (SessionAuthProcessResponse)      │
  │ • Extracts TPM nonces, new session handles, & object Names  │
  │ • Keeps harness in sync for subsequent commands in sequence │
  └─────────────────────────────────────────────────────────────┘
```

#### 2. Where Mutations Actually Occur
* **Timing:** The mutation happens **inside `libprotobuf-mutator` before the fuzz target function runs**.
* **Target:** Instead of mutating a flat byte array, mutations occur on the **Protobuf C++ object tree**:
  * **Field-level:** Adjusting integer bounds (e.g. key length), selecting valid/invalid algorithm enums, or toggling attribute bits in `TPMA_OBJECT`.
  * **Sequence-level:** Inserting a new command between existing steps, dropping a step, or duplicating an operation to test state transitions.

#### 3. Post-Processing & Normalization (`proto_postprocessors.cc`)
* Because random mutations on enums or handles can cause trivial early exits in unmarshaling, the framework registers post-processor callbacks using `protobuf_mutator::libfuzzer::PostProcessorRegistration`.
* These callbacks run immediately after mutation to enforce semantic sanity (e.g., ensuring command tags are set to `TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`, defaulting unspecified auth hashes to SHA-256, and provisioning default nonces).

#### 4. Wire Marshaling & HMAC Patching
* **Marshaling (`proto_conversion.cc`):** Translates the structured protobuf message into compliant TPM 2.0 wire format using the official `tss2_mu` (Marshal/Unmarshal) library.
* **Cryptographic Patching (`session_auth.cc`):** The TPM reference implementation verifies session HMACs before executing any command payload. If authorization fails, execution drops out immediately with `TPM_RC_AUTH_FAIL`. `SessionAuthPatchCommand()` calculates the true `cpHash`, increments session nonces, and inserts a mathematically valid HMAC so execution penetrates deep into core command handlers.
* **Response Processing:** Captures newly generated session handles, object Names, and updated `nonceTPM` values so subsequent commands in the sequence remain synchronized with TPM internal state.

### C. TPM Platform Wrapper: `src/harness/tpm_wrapper.c`
The TCG TPM Reference implementation expects platform hooks (`_plat__*`). This file wraps them:
* `TPMManufactureIfNeeded()`: Initializes NVRAM (`_plat__NVEnable`), formats it if needed (`TPM_Manufacture(0)`).
* `TPMStartup()`: Simulates hardware power-on signals (`_plat__Signal_PowerOn()`, `_plat__Signal_Reset()`).
* `TPMSendCommand()`: Selects locality (default 0) and invokes `_plat__RunCommand()`.
* `SendTPM2StartupCommand()` / `SendTPM2ShutdownCommand()`: Injects raw pre-baked command bytes for clean startup and shutdown.
* `TPMShutdown()`: Ends hashing, commits/disables NVRAM, and powers down.

### D. Reactive HMAC Session Auth Layer: `src/harness/session_auth.cc`
* **The Problem**: A TPM will immediately drop any command requiring session authorization if the HMAC does not match. Because `libFuzzer` generates random numbers, random mutation would virtually never produce a valid SHA-256 HMAC over the parameters.
* **The Solution**: A stateful in-memory interceptor:
  * Watches for `TPM2_StartAuthSession` in outgoing packets and saves the requested auth hash algorithm.
  * Captures the resulting `sessionHandle` and initial `nonceTPM` from the TPM's response.
  * Maintains a `NameTable` mapping transient and persistent object handles (`0x80xxxxxx`, `0x81xxxxxx`) to their TPM Names (generated dynamically when keys are created or loaded).
  * On every command with `TPM_ST_SESSIONS`:
    1. Computes `cpHash = Hash(commandCode || Names || commandParameters)`.
    2. Injects caller nonce `nonceCaller`.
    3. Computes `HMAC = HMAC_SHA256(sessionKey || authValue, cpHash || nonceCaller || nonceTPM || sessionAttributes)`.
    4. Patches the HMAC bytes into the authorization area before `_plat__RunCommand()` sees it!

### E. Protobuf Marshaling & Normalization: `proto_conversion.cc` & `proto_normalization.cc`
* **`proto_conversion.cc`**: Uses the official `tss2_mu` (Marshal/Unmarshal) library from `tpm2-tss` to convert structured fields (`TPM2B_PUBLIC`, `TPM2B_SENSITIVE_CREATE`, `TPML_PCR_SELECTION`, etc.) into TPM byte streams. It calculates wire sizes and updates `commandSize` in the header.
* **`proto_normalization.cc`**: Mutators often choose invalid enum values (e.g., algorithm 0, or non-existent parent handles). Normalization fixes up invariants:
  * Ensures headers have valid tags (`TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`).
  * Injects standard parent handles (`0x80000000` or `0x40000009` password session).
  * Fixes cryptographic templates (e.g. setting RSA key size to 2048, symmetric cipher to AES-128, name algorithm to SHA-256).

---

## 4. Deep Dive: The 15 Tested TPM Commands

The protobuf schema (`include/proto/tpm_commands.proto`) models 15 distinct TPM commands. Below is an explanation of what each function does inside the TPM and how it is fuzzed:

---

### 1. `TPM2_GetRandom` (`TPM_CC_GetRandom = 0x0000017B`)
* **What it does in the TPM**: Invokes the hardware/software RNG to return an array of cryptographically secure random bytes up to the requested size.
* **Fuzzing Significance**: Verifies RNG request bounds, buffer allocation limits, and whether asking for 0 or `UINT16_MAX` bytes triggers buffer overflows or state corruption.
* **Normalization**: Ensures `bytes_requested > 0` and header tag is `TPM_ST_NO_SESSIONS`.

---

### 2. `TPM2_CreatePrimary` (`TPM_CC_CreatePrimary = 0x00000131`)
* **What it does in the TPM**: Generates a Primary Object (a Root Key) derived deterministically from the TPM's primary seed inside a given hierarchy (Owner `0x40000001`, Endorsement `0x4000000B`, Platform `0x4000000C`, or Null `0x40000007`). Returns an active transient object handle (typically `0x80000000`).
* **Fuzzing Significance**: Exercises key generation math (RSA key pair generation or ECC curve point generation), template validation, and transient memory object slot allocation.
* **Normalization**: Injects valid template parameters (RSA 2048, SHA-256, decrypt/sign attributes) so the TPM does not reject the command before generating keys.

---

### 3. `TPM2_Create` (`TPM_CC_Create = 0x00000153`)
* **What it does in the TPM**: Creates a child object (key or data) under an existing parent key. The TPM generates the child key and returns its `outPrivate` (encrypted with parent's symmetric/storage key) and `outPublic`. The child key is *not* loaded into TPM RAM yet.
* **Fuzzing Significance**: Tests cryptographic binding between parent and child, encryption of sensitive parameters, and schema validation.
* **Normalization**: Requires a valid parent handle (created previously or default transient handle).

---

### 4. `TPM2_Load` (`TPM_CC_Load = 0x00000157`)
* **What it does in the TPM**: Takes the `inPrivate` and `inPublic` buffers generated by `TPM2_Create`, decrypts the private area using the parent key, verifies integrity (HMAC/Name), and loads the object into a transient RAM handle (`0x80xxxxxx`).
* **Fuzzing Significance**: High risk for memory corruption! Parsing untrusted, encrypted private blob structures, integrity tag validation, and transient object table management.
* **Normalization**: Patches `parent_handle` to `0x80000000` and configures session authorization.

---

### 5. `TPM2_StartAuthSession` (`TPM_CC_StartAuthSession = 0x00000176`)
* **What it does in the TPM**: Starts an authorization session (HMAC, Policy, or Trial session). The TPM generates an initial `nonceTPM`, allocates a session handle (`0x02xxxxxx`), and establishes an encryption/integrity channel.
* **Fuzzing Significance**: Critical for stateful fuzzing. Tests session table exhaustion, cipher negotiation (AES-CFB, XOR), and key exchange.
* **Normalization**: Defaults to HMAC session (`TPM_SE_HMAC`), `TPM_RH_NULL` bind/tpmKey, and SHA-256 digest algorithm. Intercepted by `session_auth.cc`.

---

### 6. `TPM2_RSA_Encrypt` (`TPM_CC_RSA_Encrypt = 0x00000154`)
* **What it does in the TPM**: Performs public-key encryption on input data using an loaded RSA key handle according to a specified padding scheme (e.g. OAEP, PKCS#1 v1.5, or NULL).
* **Fuzzing Significance**: Tests public RSA math, padding parser logic, buffer boundaries, and scheme rejection.

---

### 7. `TPM2_RSA_Decrypt` (`TPM_CC_RSA_Decrypt = 0x00000152`)
* **What it does in the TPM**: Uses the private portion of a loaded RSA key to decrypt a ciphertext buffer and verify/unpad the resulting plaintext.
* **Fuzzing Significance**: High-priority cryptographic target. Prone to padding oracle edge cases, improper buffer handling during unpadding, and authorization failures.
* **Normalization**: Requires session authorization and an active RSA decrypt key handle.

---

### 8. `TPM2_Clear` (`TPM_CC_Clear = 0x00000126`)
* **What it does in the TPM**: Clears all context associated with the Owner and Endorsement hierarchies. Resets the Storage Primary Seed (SPS), wiping all persistent objects and NV spaces created under the Owner hierarchy.
* **Fuzzing Significance**: Tests extreme state resets, persistent memory purging, handle invalidation, and lockout logic.
* **Normalization**: Uses `TPM_RH_LOCKOUT` or `TPM_RH_PLATFORM` authorization.

---

### 9. `TPM2_PCR_Allocate` (`TPM_CC_PCR_Allocate = 0x0000012B`)
* **What it does in the TPM**: Reconfigures which hash algorithm banks (SHA-1, SHA-256, SHA-384, etc.) are actively allocated to the Platform Configuration Registers (PCRs). Requires platform authorization and a reboot to take effect.
* **Fuzzing Significance**: Re-allocates NVRAM and internal memory arrays for PCR banks. Tests allocation edge cases and invalid bank combinations.

---

### 10. `TPM2_PCR_Event` (`TPM_CC_PCR_Event = 0x0000012D`)
* **What it does in the TPM**: Takes an arbitrary event data buffer, hashes it using all active PCR bank algorithms, and extends each selected PCR: `PCR_new = Hash(PCR_old || Hash(eventData))`.
* **Fuzzing Significance**: Tests simultaneous multi-bank hashing, varying event buffer lengths, and PCR index boundaries (0 through 23).

---

### 11. `TPM2_PCR_Read` (`TPM_CC_PCR_Read = 0x0000017E`)
* **What it does in the TPM**: Reads the current digest values from a specified selection of PCR registers across different banks. Returns a digest list and a PCR update counter.
* **Fuzzing Significance**: Exercises PCR bitmask selection parsing, buffer packing of variable digest sizes, and output serialization.

---

### 12. `TPM2_PCR_SetAuthPolicy` (`TPM_CC_PCR_SetAuthPolicy = 0x0000012C`)
* **What it does in the TPM**: Associates an authorization policy digest and hash algorithm with a specific PCR or group of PCRs, controlling who can modify them.
* **Fuzzing Significance**: Tests policy association, authorization checks, and invalid policy digest lengths.

---

### 13. `TPM2_NV_DefineSpace` (`TPM_CC_NV_DefineSpace = 0x0000012A`)
* **What it does in the TPM**: Allocates a Non-Volatile (NV) RAM index slot in the TPM with specific size, permissions (read/write rules, owner/platform policy), and attributes (ordinary, counter, bitfield, or extend index).
* **Fuzzing Significance**: Directly modifies non-volatile storage structures. Tests NV storage exhaustion, index collision handling, permission parsing, and corrupt metadata handling.

---

### 14. `TPM2_SetPrimaryPolicy` (`TPM_CC_SetPrimaryPolicy = 0x0000012E`)
* **What it does in the TPM**: Sets the authorization policy requirement for one of the primary hierarchies (Owner, Platform, or Endorsement).
* **Fuzzing Significance**: Alters fundamental access control rules for root hierarchies; tests policy validation and hierarchy authority verification.

---

### 15. `TPM2_MakeCredential` (`TPM_CC_MakeCredential = 0x00000139`)
* **What it does in the TPM**: Used in remote attestation / enrollment. Encrypts a secret credential (like an activation key) under the public key of an Endorsement Key (EK) and binds it to the Name of an Attestation Identity Key (AIK). Does not require authorization because it uses only public keys.
* **Fuzzing Significance**: Complex cryptographic operation involving asymmetric key encryption, seed generation, KDF (key derivation function), and symmetric parameter wrapping.

---

## 5. Build, Test, and Execution Workflows

### Running via Docker Compose
```bash
# Run raw byte fuzzer
docker compose run fuzzer

# Run structure-aware protobuf fuzzer
docker compose run proto-fuzzer
```

### Reproducing Crashes with `Tester`
When `libFuzzer` discovers a crash, it writes an artifact (e.g. `artifacts/crash-6c3e...` or `proto-artifacts/crash-9f1a...`).
You can inspect and reproduce the exact crash without running the fuzzer loop:
```bash
./build/Tester artifacts/crash-6c3e...
```
`Tester` parses the corpus file, prints hex and binary representations of each command, sends them to the TPM wrapper, and prints the raw TPM response.

### Generating Seeds (`tools/seed-generation`)
The Python tooling under `tools/seed-generation/` (managed via `uv`) programmatically creates valid starting test cases:
* **Why it exists:** TPM 2.0 requires strictly formatted wire packets. Starting with empty or random inputs would waste CPU cycles on syntax rejections. This tool generates syntactically valid initial seeds.
* **Architecture:**
  * `main.py` & `tpm2_commands.py`: Encodes valid command parameter combinations (Startup, CreatePrimary, PCR Read, Clear, etc.).
  * Uses compiled Protobuf code (`*_pb2.py`) to build structured objects.
* **Running the generator:**
  ```bash
  ./scripts/generate-seeds.sh
  # or directly with uv:
  cd tools/seed-generation && uv run main.py -recreate
  ```
* **Output:**
  * `seeds/bytearray/`: Raw wire-format binary command packets.
  * `seeds/proto/`: Serialized protobuf messages adhering to `TPMCommandSequence`.

### Seeds vs. Mutants vs. Artifacts
| Category | Storage Directory | Filename Format | Role |
| :--- | :--- | :--- | :--- |
| **Seeds** | `seeds/bytearray/`<br>`seeds/proto/` | Human-readable names (e.g. `TPMClear-variant0-...`) | Read-only initial inputs provided by developer or generator. |
| **New Mutants** | `corpus/`<br>`corpus-running/` | **40-character SHA-1 hash** (e.g. `3b1a8f9c0e2...`) | Inputs generated by libFuzzer that discovered **new code coverage**. |
| **Crash Artifacts** | `artifacts/`<br>`proto-artifacts/` | Prefix + SHA-1 (e.g. `crash-6c3e98...`, `timeout-...`) | Mutants that triggered ASan errors, assertion failures, or hangs. |

### How Coverage is Checked & Where Mutants are Saved

A common question is: *Where in the project source code does it check if a new line was covered and save the mutant to the corpus?*

**Answer: It is handled by LLVM Compiler Instrumentation and the libFuzzer Runtime Engine, not project code.**

1. **Compile-Time Instrumentation (`CMakeLists.txt`):**
   ```cmake
   target_compile_options(Fuzzer PRIVATE -fsanitize=fuzzer,address -fcoverage-mapping)
   ```
   When Clang compiles with `-fsanitize=fuzzer`, it injects LLVM `SanitizerCoverage` hooks (8-bit edge counters / PC tables) at **every basic block and branch** throughout both our harness and the TPM reference code (`vendor/TPM`).

2. **The libFuzzer Execution Loop (`compiler-rt/lib/fuzzer/FuzzerLoop.cpp`):**
   * LibFuzzer runs its internal execution loop:
     ```cpp
     // Inside libFuzzer runtime engine:
     Mutate(CurrentUnit);
     ResetCoverageCounters();
     LLVMFuzzerTestOneInput(CurrentUnit.Data(), CurrentUnit.Size()); // Calls src/fuzzer.cc or proto-fuzzer.cc
     bool has_new_coverage = CheckCoverageCounters();
     if (has_new_coverage) {
         PrintStats("NEW");
         WriteToOutputCorpus(CurrentUnit); // Writes to corpus-running/<sha1>
     }
     ```
3. **Corpus Merge (`start-fuzzer.sh`):**
   * At startup, `start-fuzzer.sh` passes:
     ```bash
     $FUZZER_BIN $RUN_CORPUS_DIR $CORPUS_DIR $SEEDS_DIR
     ```
   * LibFuzzer treats the **first directory** (`$RUN_CORPUS_DIR`) as the output directory.
   * Whenever an execution hits a previously unvisited basic block counter, libFuzzer names the mutant after its **SHA-1 hash** and writes it into `$RUN_CORPUS_DIR`.
   * At completion, `start-fuzzer.sh` runs `-merge=1` to deduplicate and merge all unique coverage-increasing mutants into `$CORPUS_DIR`.

---

## 6. Grill Me: Technical Knowledge Assessment

> **Test your understanding before continuing development!** The questions below cover critical aspects of this codebase, TPM 2.0 specifications, and libFuzzer mechanics.

---

### Question 1: Session Auth Bypass Trap
**Scenario:** You add a new command, `TPM2_NV_Write`, to `tpm_commands.proto`. You run the `proto-fuzzer`, but libFuzzer reports 0% new coverage on the TPM NV subsystem, and `TPMSendCommand` always returns response code `0x000001D5` (`TPM_RC_AUTH_FAIL`).
* **Why is this happening?**
* **Which file in `src/harness/` must you update, and what exact calculation is failing?**

<details>
<summary>👉 Reveal Answer</summary>

**Answer:**
`session_auth.cc` has not been taught the command attributes of `TPM2_NV_Write`!
In `session_auth.cc`, HMAC generation requires calculating `cpHash = Hash(commandCode || Names || cpBuffer)`. To do this, the harness must know:
1. How many command handles the command takes (to extract their `Names` from the `NameTable`).
2. Where the parameter area starts and ends.
If `session_auth.cc` doesn't recognize `TPM2_NV_Write`, it cannot calculate the proper `cpHash` or inject the valid session HMAC. The TPM reference implementation checks the HMAC before executing the command body and immediately aborts with `TPM_RC_AUTH_FAIL`.
</details>

---

### Question 2: The Two-Fuzzer Dilemma
**Scenario:** A colleague asks: *"Why don't we just use the Proto Fuzzer for everything? It has structure, so it's strictly better than the Byte Fuzzer, right?"*
* **How would you answer? What specific bug classes will the Byte Fuzzer find that the Proto Fuzzer will NEVER find?**

<details>
<summary>👉 Reveal Answer</summary>

**Answer:**
The Proto Fuzzer is **not** strictly better; the two fuzzers are complementary.
Because the Proto Fuzzer serializes data using `tss2_mu` and applies normalization, it always produces syntactically well-formed TPM packet structures. It will **never** generate:
1. Truncated command headers (`length < 10`).
2. Mismatched payload size indicators (e.g. `commandSize` declaring 40 bytes when only 15 bytes were sent).
3. Invalid TPM command tags (e.g. values other than `0x8001` or `0x8002`).
4. Malformed ASN.1 or corrupted internal TLV length fields in unmarshaling routines.

The **Byte Fuzzer** is specifically designed to explore parser vulnerabilities, out-of-bounds reads, and integer overflows in the low-level wire deserialization code before any command logic is reached.
</details>

---

### Question 3: Nonce Invalidation & State Desync
**Scenario:** In `proto-fuzzer.cc`, the fuzzer loops through each command in a `TPMCommandSequence`. If command #2 fails with `TPM_RC_BAD_AUTH`, why might command #3 (which has a completely valid configuration) also fail?
* **What happens to the TPM session's `nonceTPM` when a command execution or auth verification fails?**

<details>
<summary>👉 Reveal Answer</summary>

**Answer:**
According to the TPM 2.0 Specification (Part 1, Architecture, §19):
Every time a command is submitted with an active session, the TPM rolls its internal `nonceTPM` to a new random value, regardless of whether the command succeeded or failed!
If our harness desynchronizes or fails to parse the new `nonceTPM` from an error response, all subsequent commands in that sequence will compute their HMAC using a stale `nonceTPM`. This leads to **cascading authentication failures** for the remainder of the fuzz iteration.
</details>

---

### Question 4: NVRAM State Pollution
**Scenario:** While running `fuzzer`, you notice after 10,000 iterations that the fuzzer begins crashing inside `_plat__NVEnable()` with an NV storage error, or `TPM2_CreatePrimary` fails with `TPM_RC_NV_SPACE`.
* **Looking at `tpm_wrapper.c`, how does the wrapper manage NVRAM between iterations, and what could cause NV exhaustion?**

<details>
<summary>👉 Reveal Answer</summary>

**Answer:**
In `tpm_wrapper.c`, line 102:
```c
// Actual reference implementation doesn't remove the NVChip.
// We want it gone for a fresh start each run.
// _plat__TearDown();
_plat__NVDisable((void*)1, 0);
```
`TPMShutdown()` commits and disables the NV chip, but if the underlying storage file (`NVChip`) is not deleted or if `_plat__TearDown()` is commented out, persistent objects or NV spaces defined by earlier iterations persist into later iterations!
Eventually, the TPM's NVRAM capacity fills up completely, causing subsequent allocation commands to fail.
</details>

# Size-Hiding Private Set Intersection with Malicious Security

**Mutual Two-Party Variant for Small Sets and Small Domains**

---

## 1. Introduction

### 1.1 Purpose

This document specifies a cryptographic protocol for Private Set Intersection (PSI) between two mutually distrusting parties. The protocol allows both parties to learn which elements they share in common, without revealing any information about elements not in the intersection, and without revealing the size of either party's input set.

The protocol is designed for the following operational context:

- **Domain size:** The universe of possible element values |D| is small (on the order of 100).
- **Set scale:** Each party holds approximately 10 elements drawn from this domain.
- **Security model:** Malicious adversaries who may deviate arbitrarily from the protocol.
- **Privacy goal:** Neither party learns the other party's set size or any elements outside the intersection.
- **Output:** Mutual. Both parties learn the intersection.
- **Architecture:** Strictly two-party. No trusted third party or certificate authority is involved at any stage.

A small domain creates a significant enumeration risk: a malicious party could fill its input set with dictionary values to probe the honest party's elements. This protocol addresses that threat through a carefully chosen pad-to size N that is much smaller than the domain, combined with rate limiting on protocol executions. Section 6 provides a detailed analysis of this tradeoff.

### 1.2 Prior Work

This protocol builds on established techniques from the PSI literature. The foundational commutative-encryption approach was introduced by Huberman, Franklin, and Hogg (1999) and formalized by Freedman, Nissim, and Pinkas (EUROCRYPT 2004). The size-hiding variant (SHI-PSI) was first proposed by Ateniese, De Cristofaro, and Tsudik (PKC 2011), who demonstrated that hiding client set sizes incurs minimal overhead. The zero-knowledge proof techniques for malicious security draw from Chaum-Pedersen (1992) discrete-log equality proofs and Schnorr (1991) signatures of knowledge.

### 1.3 Notation

| Symbol | Meaning |
|--------|---------|
| `G` | An elliptic curve group of prime order q with generator g |
| `q` | The order of group G (a large prime, typically 256 bits) |
| `H: {0,1}* → G` | A hash-to-curve function mapping arbitrary strings to group elements |
| `S_A, S_B` | Private input sets of Party A and Party B respectively |
| `N` | Public pad-to size parameter. Fixed at 10 for this deployment |
| `\|D\|` | Size of the element domain (the universe of possible values; approximately 100) |
| `a, b ∈ Z_q` | Secret blinding keys chosen uniformly at random by Party A and Party B |
| `Com(x; r)` | A Pedersen commitment to value x with randomness r |
| `π_DL` | A zero-knowledge proof of discrete log equality (Chaum-Pedersen proof) |
| `π_Shuf` | A zero-knowledge proof of correct shuffle (permutation proof) |
| `λ` | Security parameter (e.g. 128 bits) |

---

## 2. Threat Model and Security Properties

### 2.1 Adversary Model

The protocol is secure against a malicious adversary who controls one of the two parties. The adversary may:

- Deviate arbitrarily from the protocol specification.
- Choose inputs adaptively based on messages received so far.
- Attempt to manipulate, reorder, drop, or inject messages.
- Attempt to learn information about the honest party's set beyond the intersection.

We assume the adversary is computationally bounded (probabilistic polynomial time) and that communication channels are authenticated (e.g., via TLS). We do not assume an honest majority; either party may be corrupt.

### 2.2 Security Properties

**Set privacy.** Neither party learns any element belonging to the other party's set that is not in the intersection. Formally, the view of a corrupt party can be simulated given only the intersection and the public parameters.

**Size hiding.** Neither party learns the cardinality of the other party's input set. All protocol messages are exactly the same size regardless of the actual number of real elements either party holds. This is achieved through deterministic padding to the public maximum N.

**Input independence.** The commitment phase ensures that neither party can choose their input set adaptively after observing the other party's protocol messages. Both parties commit to their blinded sets before any blinded elements are exchanged.

**Correctness.** If both parties follow the protocol honestly, both learn exactly S_A ∩ S_B and nothing else. The zero-knowledge proofs ensure that a malicious party cannot cause the honest party to compute an incorrect result (except by choosing a different input set before the protocol begins).

### 2.3 What Is Not Protected

The protocol does not hide the size of the intersection itself. Both parties learn how many elements they share. If hiding the intersection size is required, a PSI-Cardinality (PSI-CA) variant should be considered instead.

**Enumeration attacks are inherent to any PSI protocol.** A malicious party can choose its input set to be a dictionary of guessed values rather than its real secrets. Because blinded elements are cryptographically indistinguishable from one another, the honest party cannot detect whether the other side submitted real secrets or dictionary entries. This is not a flaw in the protocol — it is a fundamental property of private set intersection. Any protocol that hides set contents must also hide whether those contents are "real."

In this protocol, the enumeration surface is bounded by the pad-to parameter N. With N = 10 and a domain of 100, a malicious party can probe at most 10% of the domain per protocol execution. See Section 6 for a full analysis of this tradeoff, the rationale for the chosen parameters, and why alternative approaches involving trusted third parties were rejected.

---

## 3. Cryptographic Primitives

### 3.1 Elliptic Curve Group

We use the Ristretto255 group, which provides a prime-order group abstraction over Curve25519. This avoids cofactor complications and provides 128-bit security. The group order q is approximately 2^252.

### 3.2 Hash-to-Curve Function H

H maps arbitrary byte strings to elements of the Ristretto255 group. We use the Elligator 2 map as specified in RFC 9380 (Hashing to Elliptic Curves), Section 6.8 for Curve25519/Ristretto.

**Security requirement:** H must behave as a random oracle. No party should be able to find the discrete log of H(x) with respect to the generator g for any input x.

### 3.3 Pedersen Commitments

A Pedersen commitment scheme uses two independent generators g and h of the group G (where the discrete log of h with respect to g is unknown). To commit to a set of group elements {P_1, ..., P_N}:

    Com({P_i}; r) = r · h + Σ P_i

where r is a uniformly random scalar. The commitment is computationally binding (under the discrete log assumption) and perfectly hiding.

**In practice:** Each party commits to the multiset-hash of their blinded elements. This is computed as the sum of all blinded points plus a randomness term. The commitment is opened by revealing r and the set of points.

### 3.4 Chaum-Pedersen Proof of Consistent Exponentiation

The core zero-knowledge proof used in this protocol demonstrates that a party applied the same secret exponent to every received element. Given input points {P_1, ..., P_N} and output points {Q_1, ..., Q_N}, the prover demonstrates knowledge of a scalar k such that Q_i = k · P_i for all i.

The protocol proceeds as follows (using Fiat-Shamir heuristic for non-interactivity):

**Prover** (knows secret k):

  a) For each i, choose random v_i, compute R_i = v_i · P_i.
  b) Compute challenge: c = Hash(P_1, Q_1, R_1, ..., P_N, Q_N, R_N).
  c) Compute response: s_i = v_i - c · k (mod q) for each i.
  d) Send π = (c, {s_i}).

**Verifier:**

  a) For each i, compute R'_i = s_i · P_i + c · Q_i.
  b) Compute c' = Hash(P_1, Q_1, R'_1, ..., P_N, Q_N, R'_N).
  c) Accept if and only if c = c'.

**Batch optimization:** For efficiency, use a single random linear combination. Choose random weights w_1, ..., w_N and prove that Σ w_i · Q_i = k · (Σ w_i · P_i). This reduces the proof to a single Chaum-Pedersen instance with soundness error 1/q, which is negligible.

### 3.5 Verifiable Shuffle

After double-blinding, each party must shuffle (randomly permute) the set of elements before returning them. The shuffle must be verifiable: the shuffling party proves that the output is a permutation of the input (no elements added, removed, or modified), without revealing the permutation itself.

For small sets (N < 1000), we recommend a simple approach:

**Commitment-based shuffle proof:** The shuffling party commits to the permutation σ using a permutation matrix encoded as commitments. They then prove in zero knowledge that the matrix represents a valid permutation and that applying it to the input yields the output. This has O(N) proof size and O(N) verification time.

**Alternative (simpler, slightly less efficient):** Instead of proving the shuffle directly, the party can commit to the sorted output. Since comparing multisets is equivalent to comparing sorted sets, both parties can independently verify that the multiset of double-blinded elements is consistent with the commitment, without needing a full shuffle proof. This works because the final comparison step only needs multiset equality, not ordered equality.

---

## 4. Protocol Specification

### 4.1 Public Parameters

Before protocol execution, both parties agree on:

| Parameter | Description |
|-----------|-------------|
| `G, g, q` | Ristretto255 group, generator, and order |
| `h` | Second generator for Pedersen commitments (h = H("pedersen_generator")) |
| `N` | Pad-to size. |
| `H` | Hash-to-curve function as specified in Section 3.2 |
| `D` | The element domain (the universe from which real set elements are drawn) |

### 4.2 Phase 0: Initialization

Each party independently prepares their input.

**Party A:**

1. Let S_A = {x_1, ..., x_m} be the real input set where m ≤ N.
2. Generate N - m dummy elements d_1, ..., d_{N-m} by sampling random strings from a dummy domain D' disjoint from D (e.g., by prepending a fixed tag: d_i = "DUMMY_" || random_bytes(32)).
3. Form the padded set S'_A = {x_1, ..., x_m, d_1, ..., d_{N-m}} of exactly N elements.
4. Sample secret blinding key a ← Z_q uniformly at random.
5. Compute the blinded set: for each element e ∈ S'_A, compute P_e = a · H(e).
6. Randomly permute the blinded set to obtain T_A = σ_A({P_e}).

**Party B:** Performs the identical procedure with their set S_B and blinding key b to produce T_B.

### 4.3 Phase 1: Commitment Exchange

This phase prevents adaptive input selection.

1. Party A computes commitment C_A = Com(T_A; r_A) where r_A ← Z_q.
2. Party B computes commitment C_B = Com(T_B; r_B) where r_B ← Z_q.
3. Party A sends C_A to Party B.
4. Party B sends C_B to Party A.
5. Both parties wait until they have received the other's commitment before proceeding to Phase 2. (Simultaneous exchange can be achieved via a standard coin-toss protocol if a synchronous channel is not available.)

### 4.4 Phase 2: Blinded Set Exchange and Double-Blinding

This is the core phase where elements are double-blinded.

**Step 2a — A sends blinded set to B:**

1. Party A opens commitment C_A by sending (T_A, r_A) to Party B.
2. Party B verifies that Com(T_A; r_A) = C_A. If verification fails, abort.
3. Party B verifies that |T_A| = N. If not, abort.

**Step 2b — B double-blinds A's set and sends own set:**

1. Party B computes the double-blinded set: for each P ∈ T_A, compute Q = b · P = ab · H(e).
2. Party B generates zero-knowledge proof π_B proving consistent exponentiation: that the same scalar b was applied to every element of T_A (see Section 3.4).
3. Party B randomly permutes the double-blinded set to obtain U_AB = σ'_B({Q}).
4. Party B opens commitment C_B by sending (T_B, r_B) to Party A, along with U_AB and π_B.

**Step 2c — A verifies and double-blinds B's set:**

1. Party A verifies that Com(T_B; r_B) = C_B. If verification fails, abort.
2. Party A verifies that |T_B| = N and |U_AB| = N. If not, abort.
3. Party A verifies π_B. If verification fails, abort.
4. Party A verifies that the multiset of U_AB is consistent with b applied to T_A (the proof π_B covers this).
5. Party A computes the double-blinded set of B's elements: for each P ∈ T_B, compute Q = a · P = ba · H(e).
6. Party A generates π_A proving consistent exponentiation with scalar a.
7. Party A randomly permutes to obtain U_BA = σ'_A({Q}).
8. Party A sends U_BA and π_A to Party B.

**Step 2d — B verifies A's double-blinding:**

1. Party B verifies π_A. If verification fails, abort.

### 4.5 Phase 3: Intersection Computation

Both parties now independently compute the intersection.

**Party A holds:** U_AB (the double-blinded version of A's own elements, blinded by a then b, shuffled by B) and U_BA (the double-blinded version of B's elements, blinded by b then a, shuffled by A — A created this).

**Key property:** For any element e, the value ab · H(e) = ba · H(e) because scalar multiplication is commutative in Z_q. Therefore, if element e appears in both S_A and S_B, the corresponding double-blinded point will appear in both U_AB and U_BA.

**Computation:** Party A computes the multiset intersection I_A = U_AB ∩ U_BA. Each matching point corresponds to a shared element. Party A can identify which of their original elements are in the intersection by maintaining a mapping from double-blinded points back to original elements (this is possible because A knows a and can track the correspondence through B's shuffle by matching a · H(x_i) to its double-blinded form).

**Party B** performs the identical computation using the same two sets (B has U_AB because B created it, and received U_BA from A).

**Output:** Both parties output the set of original elements corresponding to matching double-blinded points.

---

## 5. Message Format and Communication

### 5.1 Message Summary

| Msg # | From | To | Contents |
|-------|------|----|----------|
| 1 | A | B | C_A (32 bytes: commitment to blinded set) |
| 2 | B | A | C_B (32 bytes: commitment to blinded set) |
| 3 | A | B | T_A (N × 32 bytes: blinded set), r_A (32 bytes: commitment randomness) |
| 4 | B | A | T_B (N × 32 bytes), r_B (32 bytes), U_AB (N × 32 bytes: double-blinded A), π_B (proof) |
| 5 | A | B | U_BA (N × 32 bytes: double-blinded B), π_A (proof) |

### 5.2 Communication Complexity

With Ristretto255 (32-byte points) and the batched Chaum-Pedersen proof, the total communication per party is approximately:

    Total ≈ 4 × N × 32 + O(λ) bytes

For N = 10 and λ = 128, this is approximately 1.4 KB per party, or 2.8 KB total. This is trivially small for any network, including constrained links.

### 5.3 Round Complexity

The protocol requires 3 rounds of communication (5 messages total):

- **Round 1:** Simultaneous commitment exchange (messages 1 and 2).
- **Round 2:** A sends blinded set; B responds with double-blinded set, own blinded set, and proof (messages 3 and 4).
- **Round 3:** A sends double-blinded set and proof (message 5).

---

## 6. Security Analysis

### 6.1 Security Theorem (Informal)

Under the Decisional Diffie-Hellman (DDH) assumption in the Ristretto255 group and modelling H as a random oracle, the protocol securely computes the set intersection functionality against malicious adversaries. Specifically:

**Privacy:** A corrupt Party A (resp. B) learns nothing beyond S_A ∩ S_B and the public parameter N. The simulator extracts the corrupt party's effective input from the commitment and ZK proofs, queries the ideal functionality, and simulates the remaining messages using random group elements for non-intersecting positions.

**Size hiding:** Since all messages contain exactly N group elements (regardless of the true set sizes), the transcript is computationally indistinguishable for any two input sets of different sizes, as long as both are ≤ N. The dummy elements are indistinguishable from real blinded elements under DDH.

### 6.2 Proof Sketch

**Simulator construction for corrupt Party A:**

1. Receive C_A from the adversary.
2. Send a random commitment C_B (simulated) to the adversary.
3. Receive (T_A, r_A) from the adversary. Verify the commitment opens correctly.
4. Extract the adversary's effective input set by using the ZK extractor on the proof of knowledge implicit in the commitment scheme.
5. Query the ideal PSI functionality with the extracted set to learn the intersection.
6. Simulate T_B, U_AB, and the proof π_B. For elements in the intersection, ensure the double-blinded values match. For all other positions, use random group elements.
7. Receive U_BA and π_A from the adversary (which may be malformed; the simulator verifies and aborts if invalid, matching the honest party's behavior).

The indistinguishability of the simulation relies on DDH: random group elements are indistinguishable from properly double-blinded dummy/non-intersecting elements.

### 6.3 Enumeration Attack Analysis

A malicious party could pad their set with a dictionary of likely values (rather than random dummies) to learn which elements the honest party holds. This section analyzes the threat in the context of this protocol's target deployment (domain |D| = 100, real sets of ~10 elements) and explains the chosen mitigation strategy.

#### 6.3.1 The enumeration threat in small domains

In a domain of 100 values, a malicious party that can submit N = 100 elements would learn the honest party's complete set in a single run by simply including every possible value. This is catastrophic. Even N = 50 would expose half the domain per run.

The attack cannot be detected by the honest party. Blinded elements (whether derived from real secrets or dictionary entries) are computationally indistinguishable under the DDH assumption. No verification step in the protocol can distinguish legitimate inputs from adversarial probes. This is a fundamental property, not a protocol weakness.

#### 6.3.2 Mitigation: Capping N well below |D|

The primary defense is setting the pad-to parameter N much smaller than the domain size |D|. With N = 10 and |D| = 100:

- **Per-run exposure:** An attacker can probe at most N/|D| = 10% of the domain per execution. If the honest party holds 10 elements, the expected number of elements an attacker discovers per run is approximately 10 × (10/100) = 1.
- **Runs to full enumeration:** An attacker needs at least ⌈|D|/N⌉ = 10 protocol executions to cover the entire domain.
- **Upper bound on set size:** Setting N = 10 reveals that both parties hold at most 10 elements. In this deployment, this upper bound is an acceptable disclosure since both parties already know the approximate set sizes.

#### 6.3.3 Rate limiting as a complementary control

Capping N alone is insufficient if the protocol can be executed without restriction. Rate limiting is essential:

- **One execution per party-pair per time window.** If the protocol is limited to a single execution between any two parties (or one per day/week), the attacker's enumeration is capped at N elements total.
- **Session binding.** Each protocol execution should be bound to a unique session identifier. Parties must verify that they are not engaging in a replay of a previous session.
- **Operational monitoring.** In a deployment with multiple parties, a party that initiates an unusual number of protocol executions with different counterparties may be attempting to triangulate elements and should be flagged.

## 7. Implementation Guidance

### 7.1 Performance Estimates (N = 10)

| Operation | Count | Est. Time |
|-----------|-------|-----------|
| Hash-to-curve (per party) | 10 | ~0.02 ms |
| Scalar multiplication (blinding) | 20 | ~0.5 ms |
| ZK proof generation (batched) | 1 | ~0.3 ms |
| ZK proof verification (batched) | 1 | ~0.3 ms |
| **Total per party** | — | **~1.2 ms** |
| **Total communication** | — | **~2.8 KB** |

These estimates assume a modern x86_64 processor with constant-time scalar multiplication. At N = 10, the protocol is effectively instantaneous and imposes negligible network overhead.

### 7.2 Security Considerations for Implementers

- All scalar multiplications must be constant-time to prevent timing side-channel attacks (see Section 7.3 for a detailed discussion).
- Random number generation must use a cryptographically secure PRNG (e.g., /dev/urandom, getrandom(), or equivalent).
- The hash-to-curve function must be implemented correctly per RFC 9380. An incorrect implementation can leak information about inputs.
- Dummy elements must be generated from a domain provably disjoint from the real element domain D. A simple approach: prepend a fixed tag byte (e.g., 0xFF) to random bytes, while all real elements are prepended with 0x00.
- The commitment scheme must use independent randomness for each protocol execution.
- Abort immediately on any verification failure. Do not continue the protocol or provide detailed error messages that could leak information.

### 7.3 Constant-Time Implementation

Timing side-channel attacks against scalar multiplication are a real threat: by measuring how long operations take, an attacker may recover secret blinding keys. This section describes what constant-time means, where the C# PoC falls short, and what a production implementation requires.

#### What constant-time requires

Three properties are needed throughout the field and group arithmetic:

**1. No secret-dependent branches.** The classic double-and-add scalar multiplication skips the point addition when a scalar bit is 0, directly leaking the Hamming weight and bit pattern of the secret key via timing. The fix — used by libraries such as [noble-ed25519](https://github.com/paulmillr/noble-ed25519) — is a fake-point ladder: both branches always perform a point addition, with the zero-bit case adding to a discarded accumulator:

```
// vulnerable: add only happens when bit is 1
if (bit == 1) result = result + current;

// constant-time: both branches do identical work
if (bit == 1) result = result + current;
else          fake   = fake   + current;
```

**2. No secret-dependent memory access patterns.** Windowed methods (wNAF, fixed-window) look up precomputed table entries using secret indices. Cache timing on the table lookup leaks the index. The mitigation is to read every table entry on every lookup and select the right one using a constant-time conditional move (CMOV), so all memory accesses are identical regardless of the secret.

**3. Branch-free field arithmetic.** The prime `p = 2^255 - 19` has special structure that allows branch-free modular reduction using shifts and masks rather than division. A naive `a % p` call may branch on intermediate values and take variable time depending on the magnitude of `a`.

#### Why the C# PoC is not constant-time

`System.Numerics.BigInteger` is the root cause. Its multiplication, addition, and modular reduction are variable-time: execution time depends on the actual magnitudes of the operands, not just their declared bit width. No amount of algorithmic discipline at the protocol level overcomes this — even a fake-point ladder still calls `BigInteger` field multiply internally, which leaks.

The only fix is to replace `BigInteger` with fixed-width 64-bit limb arithmetic: represent every field element as four `ulong` values and implement multiply, add, and reduce over those limbs with no branches on their contents. This is what libsodium, noble-ed25519 (via JavaScript BigInt with engine-level guarantees), and curve25519-dalek (via Rust's `u64` arithmetic) all do.

#### Path to constant-time in C#

The lowest-effort production path is P/Invoke into libsodium:

```csharp
// libsodium exposes constant-time Ristretto255 scalar multiplication
[DllImport("libsodium")]
static extern int crypto_scalarmult_ristretto255(byte[] q, byte[] n, byte[] p);
```

This replaces the entire `Ed25519` and `CryptoUtil` field arithmetic layer while leaving `PsiSession`, `ChaumPedersen`, and the message protocol untouched. The `Sodium.Core` NuGet package wraps libsodium but may not expose the low-level Ristretto255 point operations; direct P/Invoke against the native library may be required.

### 7.4 C# Proof-of-Concept Implementation

This repository includes a C# proof-of-concept (`ShiPsi.cs`) targeting .NET 9.0 that implements the full protocol. The implementation uses standard .NET libraries (`System.Security.Cryptography.SHA256`, `System.Security.Cryptography.RandomNumberGenerator`, `System.Numerics.BigInteger`) with no external dependencies.

**Differences from the specification:**

| Aspect | Specification (Sections 3–4) | C# PoC |
|--------|------------------------------|--------|
| Group | Ristretto255 (prime-order abstraction over Curve25519) | Ed25519 twisted Edwards curve with cofactor clearing (×8) |
| Commitments | Pedersen commitments (perfectly hiding, computationally binding) | Pedersen commitments: `Com({P_i}; r) = r·H + Σ P_i` where `H = HashToGroup("pedersen_generator")` |
| Hash-to-curve | Elligator 2 per RFC 9380 | Elligator 2: hash to two field elements, map each via Elligator 2 to Curve25519, convert Montgomery to Edwards, add, clear cofactor (×8) |
| Shuffle proofs | Verifiable shuffle with ZK proof (Section 3.5) | Shuffle is performed but not proven in zero knowledge |
| Chaum-Pedersen proof | Per-element with batch optimization (Section 3.4) | Batched: random linear combination of all inputs/outputs into a single proof |
| Constant-time operations | Required (Section 7.2) | Not constant-time; `BigInteger` arithmetic branches on values (see Section 7.3) |
| Field arithmetic | Native library (e.g., libsodium) | `BigInteger` with extended projective coordinates (X:Y:Z:T) to minimize field inversions |

**Architecture:**

- `Ed25519` — Curve arithmetic using extended projective coordinates (HWCD 2008 formulas). Points are represented as `(X:Y:Z:T)` internally, converted to affine `(x, y)` only for hashing and serialization.
- `CryptoUtil` — SHA-256 hashing, hash-to-group, random scalar generation, commitments, and secure shuffle.
- `ChaumPedersen` — Batched Chaum-Pedersen proof of consistent scalar multiplication. Derives deterministic weights via Fiat-Shamir and computes weighted point sums in projective coordinates.
- `PsiSession` — Full protocol state machine. Exposes `Commitment()`, `BlindedSet()`, `ProcessBlindedSet()`, `ProcessResponse()`, `ProcessFinal()`, and `Intersection()` matching the phases in Section 4.

**Performance (N = 10, measured on desktop hardware):**

| Metric | Value |
|--------|-------|
| Full protocol (two parties, local) | ~320 ms |
| Communication (serialized hex) | ~26 KB (hex-encoded; ~2.6 KB if binary) |

**To harden for production:** replace `BigInteger` EC math with libsodium P/Invoke bindings (`Sodium.Core` NuGet) for constant-time Ristretto255 operations, and add verifiable shuffle proofs.

---

## 8. Extensions and Variants

### 8.1 PSI-Cardinality (PSI-CA)

If parties should learn only the number of shared elements (not which elements are shared), the protocol can be modified. Instead of revealing the double-blinded sets, each party commits to their set and both engage in a secure cardinality computation over the committed double-blinded values. This can be achieved using an oblivious PRF and a counting protocol.

### 8.2 Updatable PSI

If the parties' sets change over time and they wish to recompute the intersection without re-running the full protocol, an updatable variant can be used. Recent work (Liu et al., 2026) demonstrates that updatable PSI can be built from mostly symmetric-key primitives, with costs proportional only to the number of changed elements. Integrating size-hiding into updatable PSI remains an active research area.

### 8.3 Multi-Party Extension

This protocol is specified for two parties. Extension to n parties requires a different approach, such as the OPPRF-based multi-party PSI of Kolesnikov et al. (CCS 2017), combined with size-hiding techniques from Zhan et al. (2023) using Bloom filters and threshold homomorphic encryption. The complexity grows significantly with the number of parties.

### 8.4 Threshold PSI

A threshold variant reveals the intersection only if its cardinality exceeds a minimum threshold t. This prevents information leakage when the intersection is very small (and thus potentially identifying). This can be implemented by adding a secure comparison sub-protocol after the cardinality computation step.

---

## 9. References

- **[ACT11]** G. Ateniese, E. De Cristofaro, G. Tsudik. "(If) Size Matters: Size-Hiding Private Set Intersection." PKC 2011.
- **[BTF16]** T. Bradley, S. Faber, G. Tsudik. "Bounded Size-Hiding Private Set Intersection." SCN 2016.
- **[CP92]** D. Chaum, T. Pedersen. "Wallet Databases with Observers." CRYPTO 1992.
- **[DCT10]** E. De Cristofaro, G. Tsudik. "Practical Private Set Intersection Protocols with Linear Complexity." FC 2010.
- **[FM25]** F. Falzon, E.A. Markatou. "Re-visiting Authorized Private Set Intersection: A New Privacy-Preserving Variant and Two Protocols." PoPETS 2025.
- **[FNP04]** M. Freedman, K. Nissim, B. Pinkas. "Efficient Private Matching and Set Intersection." EUROCRYPT 2004.
- **[HFH99]** B. Huberman, M. Franklin, T. Hogg. "Enhancing Privacy and Trust in Electronic Communities." ACM EC 1999.
- **[KKRT17]** V. Kolesnikov, R. Kumaresan, M. Rosulek, N. Trieu. "Efficient Batched Oblivious PRF with Applications to Private Set Intersection." CCS 2017.
- **[LMR+26]** J. Liu, P. Miao, M. Rosulek, X. Shi, J. Wang. "Updatable Private Set Intersection from Symmetric-Key Techniques." ePrint 2026/438.
- **[RFC9380]** IRTF CFRG. "Hashing to Elliptic Curves." RFC 9380, 2023.
- **[Sch91]** C. Schnorr. "Efficient Signature Generation by Smart Cards." Journal of Cryptology, 1991.
- **[ZZL+23]** Y. Zhan, Z. Zhang, Q. Liu et al. "Hiding the Input-Size in Multi-Party Private Set Intersection." Designs, Codes and Cryptography, 2023.
// PsiSession.cs — SHI-PSI protocol state machine and message types

using System.Security.Cryptography;
using System.Text;

namespace ShiPsiCs;

// ================================================================
// Role and phase enums — enforce the protocol state machine
// ================================================================

public enum PartyRole { Initiator, Responder }

public enum ProtocolPhase
{
    Created,               // pre-commitment-exchange
    CommitmentReceived,    // after ReceiveCommitment
    BlindedSetProcessed,   // Responder only, after ProcessBlindedSet
    Complete,              // intersection is now computable
}

// ================================================================
// Protocol messages
// ================================================================

public record BlindedSetMsg(byte[][] Points, byte[] Nonce);
public record ProcessBlindedSetResponse(
    byte[][] DoubleBlinded, CpProof Proof,
    byte[][] MyPoints, byte[] MyNonce);
public record ProcessResponseResult(
    byte[][] DoubleBlinded, CpProof Proof);

// ================================================================
// SHI-PSI Session
// ================================================================

public class PsiSession : IDisposable
{
    public const int DefaultN = 10;

    // Per README §7.2: real elements are prefixed with 0x00 and padding with
    // 0xFF inside the hash payload. The two namespaces are provably disjoint
    // because 0xFF is never a valid leading byte of a UTF-8 string. The
    // protocol DST passed to HashToPoint provides a second layer of
    // separation against any other protocol using the same Ristretto255
    // from_hash construction.
    private const string ProtocolDst = "shi_psi";
    private const byte   RealTag     = 0x00;
    private const byte   PadTag      = 0xFF;

    private readonly int _n;
    private readonly byte[] _key;
    private readonly byte[][] _blindedPoints;
    private readonly byte[] _commitNonce;
    private readonly byte[] _myCommitment;
    private readonly Dictionary<byte[], string> _myBlindedMap;

    // Fiat-Shamir transcript binding (Section 3.4)
    private readonly byte[] _sid;
    private readonly string _myId;
    private readonly string _theirId;

    private byte[]? _theirCommitment;
    private byte[][]? _myDoubleBlinded;
    private byte[][]? _theirDoubleBlinded;
    private bool _disposed;

    public PartyRole Role { get; }
    public ProtocolPhase Phase { get; private set; } = ProtocolPhase.Created;

    /// <summary>
    /// Build a SHI-PSI session.
    /// </summary>
    /// <param name="myElements">
    /// Real input set. The protocol operates on sets, so duplicates in this
    /// array are silently dropped before padding (a protocol with two copies
    /// of the same secret cannot reveal anything more than a protocol with
    /// one). After deduplication, the set must contain at most N elements.
    /// </param>
    public PsiSession(string[] myElements, byte[] sid, string myId, string theirId, PartyRole role, int n = DefaultN)
    {
        if (sid == null || sid.Length == 0)
            throw new ArgumentException("Session ID (sid) must be non-empty");
        if (string.IsNullOrEmpty(myId))
            throw new ArgumentException("Party ID (myId) must be non-empty");
        if (string.IsNullOrEmpty(theirId))
            throw new ArgumentException("Party ID (theirId) must be non-empty");
        if (n < 1)
            throw new ArgumentException($"N must be at least 1, got {n}");

        // Deduplicate: the protocol operates on sets, not multisets.
        var distinct = myElements.Distinct().ToArray();
        if (distinct.Length > n)
            throw new ArgumentException($"Set size {distinct.Length} exceeds N={n}");

        _n       = n;
        _sid     = (byte[])sid.Clone();
        _myId    = myId;
        _theirId = theirId;
        Role     = role;
        _key     = Ristretto255.RandomScalar();
        _myBlindedMap = new Dictionary<byte[], string>(distinct.Length, ByteArrayComparer.Instance);

        // Phase 0: hash (real vs padding tagged), blind, shuffle. Real elements
        // occupy positions [0, distinct.Length); padding fills the rest. Only
        // real positions are recorded in _myBlindedMap, so Intersection() can
        // distinguish them by map lookup alone — no domain-tag check needed.
        var blindedList = new byte[n][];
        int realCount = distinct.Length;
        if (n < CryptoUtil.ParallelThreshold)
        {
            for (int i = 0; i < n; i++)
                blindedList[i] = BlindOne(i, realCount, distinct);
        }
        else
        {
            Parallel.For(0, n, i =>
                blindedList[i] = BlindOne(i, realCount, distinct));
        }
        for (int i = 0; i < realCount; i++)
            _myBlindedMap[blindedList[i]] = distinct[i];
        CryptoUtil.SecureShuffle(blindedList.AsSpan());
        _blindedPoints = blindedList;

        _commitNonce  = Ristretto255.RandomScalar();
        _myCommitment = CryptoUtil.Commit(_blindedPoints, _commitNonce);
    }

    private byte[] BlindOne(int i, int realCount, string[] distinct)
    {
        var h = i < realCount ? HashRealElement(distinct[i]) : HashPadElement();
        return Ristretto255.ScalarMul(h, _key);
    }

    private static byte[] HashRealElement(string element)
    {
        var elemBytes = Encoding.UTF8.GetBytes(element);
        var input = new byte[1 + elemBytes.Length];
        input[0] = RealTag;
        elemBytes.CopyTo(input, 1);
        return Ristretto255.HashToPoint(ProtocolDst, input);
    }

    private static byte[] HashPadElement()
    {
        Span<byte> input = stackalloc byte[1 + 32];
        input[0] = PadTag;
        RandomNumberGenerator.Fill(input[1..]);
        return Ristretto255.HashToPoint(ProtocolDst, input);
    }

    // ── Role/phase gating ────────────────────────────────────────

    private void RequireRole(PartyRole required, string method)
    {
        if (Role != required)
            throw new InvalidOperationException(
                $"{method} may only be called by the {required}; this session is the {Role}");
    }

    private void RequirePhase(ProtocolPhase required, string method)
    {
        if (Phase != required)
            throw new InvalidOperationException(
                $"{method} requires phase {required}, but session is in {Phase}");
    }

    // ── Commitment exchange ──────────────────────────────────────

    public byte[] Commitment() => (byte[])_myCommitment.Clone();

    public void ReceiveCommitment(byte[] commitment)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        if (commitment.Length != Ristretto255.PointBytes)
            throw new ArgumentException(
                $"Commitment must be {Ristretto255.PointBytes} bytes, got {commitment.Length}");
        RequirePhase(ProtocolPhase.Created, nameof(ReceiveCommitment));
        _theirCommitment = (byte[])commitment.Clone();
        Phase = ProtocolPhase.CommitmentReceived;
    }

    // ── Blinded set exchange ─────────────────────────────────────

    public BlindedSetMsg BlindedSet() => new(ClonePoints(_blindedPoints), (byte[])_commitNonce.Clone());

    // ── Core protocol logic ──────────────────────────────────────

    private static byte[][] ClonePoints(byte[][] points)
    {
        var copy = new byte[points.Length][];
        for (int i = 0; i < points.Length; i++)
            copy[i] = (byte[])points[i].Clone();
        return copy;
    }

    private void ValidatePoints(byte[][] points, string label)
    {
        if (points.Length != _n)
            throw new InvalidOperationException(
                $"{label}: expected {_n} points, got {points.Length}");
        for (int i = 0; i < points.Length; i++)
        {
            if (points[i] is null || points[i].Length != Ristretto255.PointBytes)
                throw new InvalidOperationException(
                    $"{label}[{i}]: expected {Ristretto255.PointBytes}-byte point, got " +
                    (points[i] is null ? "null" : points[i].Length.ToString()));
        }
    }

    private static void ValidateScalar(byte[] scalar, string label)
    {
        if (scalar is null || scalar.Length != Ristretto255.ScalarBytes)
            throw new InvalidOperationException(
                $"{label}: expected {Ristretto255.ScalarBytes}-byte scalar, got " +
                (scalar is null ? "null" : scalar.Length.ToString()));
    }

    private void VerifyCommitment(byte[][] points, byte[] nonce)
    {
        ValidatePoints(points, "blinded set");
        ValidateScalar(nonce, "commitment nonce");
        if (!CryptoUtil.VerifyCommit(points, nonce, _theirCommitment!))
            throw new InvalidOperationException("Commitment verification failed");
    }

    // Canonical commitment ordering ensures prover and verifier
    // include both commitments in the same deterministic order.
    private FiatShamirContext ProveContext()
    {
        var (c1, c2) = CryptoUtil.CanonicalOrder(_myCommitment, _theirCommitment!);
        return new FiatShamirContext(_sid, _myId, _theirId, c1, c2);
    }

    private FiatShamirContext VerifyContext()
    {
        var (c1, c2) = CryptoUtil.CanonicalOrder(_myCommitment, _theirCommitment!);
        return new FiatShamirContext(_sid, _theirId, _myId, c1, c2);
    }

    private void VerifyProof(byte[][] doubleBlinded, CpProof proof)
    {
        ValidatePoints(doubleBlinded, "double-blinded set");
        ValidateScalar(proof?.C!, "proof.C");
        ValidateScalar(proof?.S!, "proof.S");
        if (!ChaumPedersen.Verify(_blindedPoints, doubleBlinded, proof!, VerifyContext()))
            throw new InvalidOperationException("Consistency proof verification failed");
    }

    private (byte[][] doubled, CpProof proof) DoubleBlindAndProve(byte[][] theirPoints)
    {
        var doubled = new byte[_n][];
        if (_n < CryptoUtil.ParallelThreshold)
        {
            for (int i = 0; i < _n; i++)
                doubled[i] = Ristretto255.ScalarMul(theirPoints[i], _key);
        }
        else
        {
            Parallel.For(0, _n, i =>
                doubled[i] = Ristretto255.ScalarMul(theirPoints[i], _key));
        }

        var proof = ChaumPedersen.Prove(theirPoints, doubled, _key, ProveContext());
        return (doubled, proof);
    }

    // ── Protocol methods ─────────────────────────────────────────

    public ProcessBlindedSetResponse ProcessBlindedSet(BlindedSetMsg msg)
    {
        RequireRole(PartyRole.Responder, nameof(ProcessBlindedSet));
        RequirePhase(ProtocolPhase.CommitmentReceived, nameof(ProcessBlindedSet));
        VerifyCommitment(msg.Points, msg.Nonce);

        var (doubled, proof) = DoubleBlindAndProve(msg.Points);
        _theirDoubleBlinded = doubled;
        Phase = ProtocolPhase.BlindedSetProcessed;

        return new ProcessBlindedSetResponse(
            doubled, proof, _blindedPoints, _commitNonce);
    }

    public ProcessResponseResult ProcessResponse(ProcessBlindedSetResponse msg)
    {
        RequireRole(PartyRole.Initiator, nameof(ProcessResponse));
        RequirePhase(ProtocolPhase.CommitmentReceived, nameof(ProcessResponse));
        VerifyCommitment(msg.MyPoints, msg.MyNonce);
        VerifyProof(msg.DoubleBlinded, msg.Proof);

        _myDoubleBlinded = msg.DoubleBlinded;

        var (doubled, proof) = DoubleBlindAndProve(msg.MyPoints);
        _theirDoubleBlinded = doubled;
        Phase = ProtocolPhase.Complete;

        return new ProcessResponseResult(doubled, proof);
    }

    public void ProcessFinal(ProcessResponseResult msg)
    {
        RequireRole(PartyRole.Responder, nameof(ProcessFinal));
        RequirePhase(ProtocolPhase.BlindedSetProcessed, nameof(ProcessFinal));
        VerifyProof(msg.DoubleBlinded, msg.Proof);
        _myDoubleBlinded = msg.DoubleBlinded;
        Phase = ProtocolPhase.Complete;
    }

    // ── Intersection computation ─────────────────────────────────

    public string[] Intersection()
    {
        RequirePhase(ProtocolPhase.Complete, nameof(Intersection));

        var theirSet = new HashSet<byte[]>(_n, ByteArrayComparer.Instance);
        for (int i = 0; i < _theirDoubleBlinded!.Length; i++)
            theirSet.Add(_theirDoubleBlinded[i]);

        var result = new List<string>();
        for (int i = 0; i < _blindedPoints.Length; i++)
        {
            if (!theirSet.Contains(_myDoubleBlinded![i])) continue;
            if (_myBlindedMap.TryGetValue(_blindedPoints[i], out var element))
                result.Add(element);
        }
        return result.ToArray();
    }

    // ── Disposal ─────────────────────────────────────────────────

    /// <summary>
    /// Zero secret material (key and commitment nonce). Idempotent. After
    /// disposal the session is no longer usable, but already-returned messages
    /// (commitment, blinded set, proof) remain valid since they were defensively
    /// cloned at the public-API boundary.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_commitNonce);
        GC.SuppressFinalize(this);
    }

    // ── In-process protocol execution ────────────────────────────

    public static (string[] Alice, string[] Bob) RunProtocol(
        string[] setA, string[] setB, int n = DefaultN,
        byte[]? sid = null, string idA = "party_a", string idB = "party_b")
    {
        var sessionSid = sid ?? CryptoUtil.GetRandomBytes(16);
        var alice = new PsiSession(setA, sessionSid, idA, idB, PartyRole.Initiator, n);
        var bob   = new PsiSession(setB, sessionSid, idB, idA, PartyRole.Responder, n);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var msgB1 = bob.ProcessBlindedSet(alice.BlindedSet());
        var msgA2 = alice.ProcessResponse(msgB1);
        bob.ProcessFinal(msgA2);

        return (alice.Intersection(), bob.Intersection());
    }
}

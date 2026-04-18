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

public class PsiSession
{
    public const int DefaultN = 10;

    // Byte-level domain separation between real elements and padding, per
    // README § 7.2: real elements are hashed with a leading 0x00 tag, padding
    // elements with a leading 0xFF tag. No real UTF-8 string ever hashes into
    // the padding namespace, so the two domains are provably disjoint.
    private const byte RealTag = 0x00;
    private const byte PadTag  = 0xFF;

    private readonly int _n;
    private readonly byte[] _key;
    private readonly byte[][] _blindedPoints;
    private readonly byte[] _commitNonce;
    private readonly byte[] _myCommitment;
    private readonly Dictionary<string, string> _myBlindedMap = [];

    // Fiat-Shamir transcript binding (Section 3.4)
    private readonly byte[] _sid;
    private readonly string _myId;
    private readonly string _theirId;

    private byte[]? _theirCommitment;
    private byte[][]? _myDoubleBlinded;
    private byte[][]? _theirDoubleBlinded;

    public PartyRole Role { get; }
    public ProtocolPhase Phase { get; private set; } = ProtocolPhase.Created;

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
        _sid     = sid;
        _myId    = myId;
        _theirId = theirId;
        Role     = role;
        _key     = Ristretto255.RandomScalar();

        // Phase 0: hash (real vs padding tagged), blind, shuffle. Real elements
        // occupy positions [0, distinct.Length); padding fills the rest. Only
        // real positions are recorded in _myBlindedMap, so Intersection() can
        // distinguish them by map lookup alone — no string-prefix check needed.
        var blindedList = new byte[n][];
        int realCount = distinct.Length;
        Parallel.For(0, n, i =>
        {
            var h = i < realCount ? HashRealElement(distinct[i]) : HashPadElement();
            blindedList[i] = Ristretto255.ScalarMul(h, _key);
        });
        for (int i = 0; i < realCount; i++)
            _myBlindedMap[Ristretto255.PointToHex(blindedList[i])] = distinct[i];
        _blindedPoints = CryptoUtil.SecureShuffle(blindedList);

        _commitNonce  = Ristretto255.RandomScalar();
        _myCommitment = CryptoUtil.Commit(_blindedPoints, _commitNonce);
    }

    private static byte[] HashRealElement(string element)
    {
        var elemBytes = Encoding.UTF8.GetBytes(element);
        var input = new byte[1 + elemBytes.Length];
        input[0] = RealTag;
        elemBytes.CopyTo(input, 1);
        return Ristretto255.HashToPoint(input);
    }

    private static byte[] HashPadElement()
    {
        Span<byte> input = stackalloc byte[1 + 32];
        input[0] = PadTag;
        RandomNumberGenerator.Fill(input[1..]);
        return Ristretto255.HashToPoint(input);
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

    public byte[] Commitment() => _myCommitment;

    public void ReceiveCommitment(byte[] commitment)
    {
        RequirePhase(ProtocolPhase.Created, nameof(ReceiveCommitment));
        _theirCommitment = commitment;
        Phase = ProtocolPhase.CommitmentReceived;
    }

    // ── Blinded set exchange ─────────────────────────────────────

    public BlindedSetMsg BlindedSet() => new(_blindedPoints, _commitNonce);

    // ── Core protocol logic ──────────────────────────────────────

    private void VerifyCommitment(byte[][] points, byte[] nonce)
    {
        if (points.Length != _n)
            throw new InvalidOperationException($"Expected {_n} points, got {points.Length}");
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
        if (doubleBlinded.Length != _n)
            throw new InvalidOperationException($"Expected {_n} double-blinded points");
        if (!ChaumPedersen.Verify(_blindedPoints, doubleBlinded, proof, VerifyContext()))
            throw new InvalidOperationException("Consistency proof verification failed");
    }

    private (byte[][] doubled, CpProof proof) DoubleBlindAndProve(byte[][] theirPoints)
    {
        var doubled = new byte[_n][];
        Parallel.For(0, _n, i =>
            doubled[i] = Ristretto255.ScalarMul(theirPoints[i], _key));

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

        var theirSet = new HashSet<string>(_n);
        for (int i = 0; i < _theirDoubleBlinded!.Length; i++)
            theirSet.Add(Ristretto255.PointToHex(_theirDoubleBlinded[i]));

        var result = new List<string>();
        for (int i = 0; i < _blindedPoints.Length; i++)
        {
            var dbHex = Ristretto255.PointToHex(_myDoubleBlinded![i]);
            if (!theirSet.Contains(dbHex)) continue;

            var bpHex = Ristretto255.PointToHex(_blindedPoints[i]);
            if (_myBlindedMap.TryGetValue(bpHex, out var element))
                result.Add(element);
        }
        return result.ToArray();
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

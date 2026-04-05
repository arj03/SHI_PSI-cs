// PsiSession.cs — SHI-PSI protocol state machine and message types

namespace ShiPsiCs;

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
    private const string DummyTag = "DUMMY_";

    private readonly int _n;
    private readonly byte[] _key;
    private readonly byte[][] _blindedPoints;
    private readonly byte[] _commitNonce;
    private readonly byte[] _myCommitment;
    private readonly Dictionary<string, string> _myBlindedMap = new();

    // Fiat-Shamir transcript binding (Section 3.4)
    private readonly byte[] _sid;
    private readonly string _myId;
    private readonly string _theirId;

    private byte[]? _theirCommitment;
    private byte[][]? _myDoubleBlinded;
    private byte[][]? _theirDoubleBlinded;

    public PsiSession(string[] myElements, byte[] sid, string myId, string theirId, int n = DefaultN)
    {
        if (sid == null || sid.Length == 0)
            throw new ArgumentException("Session ID (sid) must be non-empty");
        if (string.IsNullOrEmpty(myId))
            throw new ArgumentException("Party ID (myId) must be non-empty");
        if (string.IsNullOrEmpty(theirId))
            throw new ArgumentException("Party ID (theirId) must be non-empty");

        // Deduplicate: the protocol operates on sets, not multisets.
        var distinct = myElements.Distinct().ToArray();
        if (distinct.Length > n)
            throw new ArgumentException($"Set size {distinct.Length} exceeds N={n}");

        _n       = n;
        _sid     = sid;
        _myId    = myId;
        _theirId = theirId;
        _key     = Ristretto255.RandomScalar();

        // Phase 0: pad, blind, shuffle
        var padded = new string[n];
        for (int i = 0; i < distinct.Length; i++)
            padded[i] = distinct[i];
        for (int i = distinct.Length; i < n; i++)
            padded[i] = DummyTag + Convert.ToHexString(CryptoUtil.GetRandomBytes(16));

        var blindedList = new byte[n][];
        Parallel.For(0, n, i =>
        {
            blindedList[i] = Ristretto255.ScalarMul(Ristretto255.HashToPoint(padded[i]), _key);
        });
        for (int i = 0; i < n; i++)
            _myBlindedMap[Ristretto255.PointToHex(blindedList[i])] = padded[i];
        _blindedPoints = CryptoUtil.SecureShuffle(blindedList);

        _commitNonce  = Ristretto255.RandomScalar();
        _myCommitment = CryptoUtil.Commit(_blindedPoints, _commitNonce);
    }

    // ── Commitment exchange ──────────────────────────────────────

    public byte[] Commitment() => _myCommitment;

    public void ReceiveCommitment(byte[] commitment) =>
        _theirCommitment = commitment;

    // ── Blinded set exchange ─────────────────────────────────────

    public BlindedSetMsg BlindedSet() => new(_blindedPoints, _commitNonce);

    // ── Core protocol logic ──────────────────────────────────────

    private void VerifyCommitment(byte[][] points, byte[] nonce)
    {
        if (_theirCommitment == null)
            throw new InvalidOperationException(
                "ReceiveCommitment must be called before processing messages");
        if (points.Length != _n)
            throw new InvalidOperationException($"Expected {_n} points, got {points.Length}");
        if (!CryptoUtil.VerifyCommit(points, nonce, _theirCommitment))
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
        VerifyCommitment(msg.Points, msg.Nonce);

        var (doubled, proof) = DoubleBlindAndProve(msg.Points);
        _theirDoubleBlinded = doubled;

        return new ProcessBlindedSetResponse(
            doubled, proof, _blindedPoints, _commitNonce);
    }

    public ProcessResponseResult ProcessResponse(ProcessBlindedSetResponse msg)
    {
        VerifyCommitment(msg.MyPoints, msg.MyNonce);

        VerifyProof(msg.DoubleBlinded, msg.Proof);

        _myDoubleBlinded = msg.DoubleBlinded;

        var (doubled, proof) = DoubleBlindAndProve(msg.MyPoints);
        _theirDoubleBlinded = doubled;

        return new ProcessResponseResult(doubled, proof);
    }

    public void ProcessFinal(ProcessResponseResult msg)
    {
        VerifyProof(msg.DoubleBlinded, msg.Proof);
        _myDoubleBlinded = msg.DoubleBlinded;
    }

    // ── Intersection computation ─────────────────────────────────

    public string[] Intersection()
    {
        if (_myDoubleBlinded == null || _theirDoubleBlinded == null)
            throw new InvalidOperationException("Protocol not complete");

        var theirSet = new HashSet<string>(_n);
        for (int i = 0; i < _theirDoubleBlinded.Length; i++)
            theirSet.Add(Ristretto255.PointToHex(_theirDoubleBlinded[i]));

        var result = new List<string>();
        for (int i = 0; i < _blindedPoints.Length; i++)
        {
            var dbHex = Ristretto255.PointToHex(_myDoubleBlinded[i]);
            if (!theirSet.Contains(dbHex)) continue;

            var bpHex = Ristretto255.PointToHex(_blindedPoints[i]);
            if (_myBlindedMap.TryGetValue(bpHex, out var element) && !element.StartsWith(DummyTag))
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
        var alice = new PsiSession(setA, sessionSid, idA, idB, n);
        var bob   = new PsiSession(setB, sessionSid, idB, idA, n);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var msgB1 = bob.ProcessBlindedSet(alice.BlindedSet());
        var msgA2 = alice.ProcessResponse(msgB1);
        bob.ProcessFinal(msgA2);

        return (alice.Intersection(), bob.Intersection());
    }
}

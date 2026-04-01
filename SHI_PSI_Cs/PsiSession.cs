// PsiSession.cs — SHI-PSI protocol state machine and message types

namespace ShiPsiCs;

// ================================================================
// Protocol messages
// ================================================================

public record CommitmentMsg(string Commitment);
public record BlindedSetMsg(string[] Points, string Nonce);
public record ProofMsg(string C, string S);
public record ProcessBlindedSetResponse(string[] OrderedDoubleBlinded, string[] DoubleBlinded, ProofMsg Proof, string[] MyPoints, string MyNonce);
public record ProcessResponseResult(string[] OrderedDoubleBlinded, string[] DoubleBlinded, ProofMsg Proof);

// ================================================================
// SHI-PSI Session (Ristretto255 via libsodium)
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

    private byte[]? _theirCommitment;
    private byte[][]? _theirBlinded;
    private byte[][]? _myDoubleBlinded;
    private byte[][]? _theirDoubleBlinded;

    public PsiSession(string[] myElements, int n = DefaultN)
    {
        if (myElements.Length > n)
            throw new ArgumentException($"Set size {myElements.Length} exceeds N={n}");

        _n   = n;
        _key = Ristretto255.RandomScalar();

        // Phase 0: pad, blind, shuffle
        var padded = new List<string>(myElements);
        while (padded.Count < n)
            padded.Add(DummyTag + Convert.ToHexString(CryptoUtil.GetRandomBytes(16)));

        var blindedList = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            var bp = Ristretto255.ScalarMul(Ristretto255.HashToPoint(padded[i]), _key);
            blindedList[i] = bp;
            _myBlindedMap[Ristretto255.PointToHex(bp)] = padded[i];
        }
        _blindedPoints = CryptoUtil.SecureShuffle(blindedList);

        _commitNonce  = Ristretto255.RandomScalar();
        _myCommitment = CryptoUtil.Commit(_blindedPoints, _commitNonce);
    }

    public CommitmentMsg Commitment() => new(Ristretto255.PointToHex(_myCommitment));

    public void ReceiveCommitment(CommitmentMsg msg)
    {
        _theirCommitment = Ristretto255.HexToPoint(msg.Commitment);
    }

    public BlindedSetMsg BlindedSet() => new(
        _blindedPoints.Select(Ristretto255.PointToHex).ToArray(),
        Convert.ToHexString(_commitNonce));

    public ProcessBlindedSetResponse ProcessBlindedSet(BlindedSetMsg msg)
    {
        var theirPoints = msg.Points.Select(Ristretto255.HexToPoint).ToArray();
        var theirNonce  = Convert.FromHexString(msg.Nonce);

        if (!CryptoUtil.VerifyCommit(theirPoints, theirNonce, _theirCommitment!))
            throw new InvalidOperationException("Commitment verification failed");
        if (theirPoints.Length != _n)
            throw new InvalidOperationException($"Expected {_n} points, got {theirPoints.Length}");

        _theirBlinded = theirPoints;

        var doubled = theirPoints.Select(p => Ristretto255.ScalarMul(p, _key)).ToArray();
        var proof   = ChaumPedersen.Prove(theirPoints, doubled, _key);
        var shuffled = CryptoUtil.SecureShuffle(doubled);
        _theirDoubleBlinded = shuffled;

        return new ProcessBlindedSetResponse(
            doubled.Select(Ristretto255.PointToHex).ToArray(),
            shuffled.Select(Ristretto255.PointToHex).ToArray(),
            new ProofMsg(Ristretto255.PointToHex(proof.C), Ristretto255.PointToHex(proof.S)),
            _blindedPoints.Select(Ristretto255.PointToHex).ToArray(),
            Convert.ToHexString(_commitNonce));
    }

    public ProcessResponseResult ProcessResponse(ProcessBlindedSetResponse msg)
    {
        var theirPoints = msg.MyPoints.Select(Ristretto255.HexToPoint).ToArray();
        var theirNonce  = Convert.FromHexString(msg.MyNonce);

        if (!CryptoUtil.VerifyCommit(theirPoints, theirNonce, _theirCommitment!))
            throw new InvalidOperationException("Commitment verification failed");
        if (theirPoints.Length != _n)
            throw new InvalidOperationException($"Expected {_n} points, got {theirPoints.Length}");

        var orderedDoubled = msg.OrderedDoubleBlinded.Select(Ristretto255.HexToPoint).ToArray();
        var shuffledDoubled = msg.DoubleBlinded.Select(Ristretto255.HexToPoint).ToArray();
        var proof = new CpProof(
            Ristretto255.HexToPoint(msg.Proof.C),
            Ristretto255.HexToPoint(msg.Proof.S));

        if (orderedDoubled.Length != _n || shuffledDoubled.Length != _n)
            throw new InvalidOperationException($"Expected {_n} double-blinded points");
        if (!ChaumPedersen.Verify(_blindedPoints, orderedDoubled, proof))
            throw new InvalidOperationException("Consistency proof verification failed");
        if (!CryptoUtil.VerifyShuffleMultiset(orderedDoubled, shuffledDoubled))
            throw new InvalidOperationException("Multiset shuffle verification failed");

        _theirBlinded   = theirPoints;
        _myDoubleBlinded = orderedDoubled;

        var theirDoubled = theirPoints.Select(p => Ristretto255.ScalarMul(p, _key)).ToArray();
        var myProof      = ChaumPedersen.Prove(theirPoints, theirDoubled, _key);
        var myShuffled   = CryptoUtil.SecureShuffle(theirDoubled);
        _theirDoubleBlinded = myShuffled;

        return new ProcessResponseResult(
            theirDoubled.Select(Ristretto255.PointToHex).ToArray(),
            myShuffled.Select(Ristretto255.PointToHex).ToArray(),
            new ProofMsg(Ristretto255.PointToHex(myProof.C), Ristretto255.PointToHex(myProof.S)));
    }

    public void ProcessFinal(ProcessResponseResult msg)
    {
        var orderedDoubled  = msg.OrderedDoubleBlinded.Select(Ristretto255.HexToPoint).ToArray();
        var shuffledDoubled = msg.DoubleBlinded.Select(Ristretto255.HexToPoint).ToArray();
        var proof = new CpProof(
            Ristretto255.HexToPoint(msg.Proof.C),
            Ristretto255.HexToPoint(msg.Proof.S));

        if (orderedDoubled.Length != _n || shuffledDoubled.Length != _n)
            throw new InvalidOperationException($"Expected {_n} double-blinded points");
        if (!ChaumPedersen.Verify(_blindedPoints, orderedDoubled, proof))
            throw new InvalidOperationException("Consistency proof verification failed");
        if (!CryptoUtil.VerifyShuffleMultiset(orderedDoubled, shuffledDoubled))
            throw new InvalidOperationException("Multiset shuffle verification failed");

        _myDoubleBlinded = orderedDoubled;
    }

    public string[] Intersection()
    {
        if (_myDoubleBlinded == null || _theirDoubleBlinded == null)
            throw new InvalidOperationException("Protocol not complete");

        var mySet        = new HashSet<string>(_myDoubleBlinded.Select(Ristretto255.PointToHex));
        var matchingHexes = new HashSet<string>(
            _theirDoubleBlinded.Select(Ristretto255.PointToHex).Where(h => mySet.Contains(h)));

        var result = new List<string>();
        for (int i = 0; i < _blindedPoints.Length; i++)
        {
            var dbHex = Ristretto255.PointToHex(_myDoubleBlinded[i]);
            if (matchingHexes.Contains(dbHex))
            {
                var bpHex = Ristretto255.PointToHex(_blindedPoints[i]);
                if (_myBlindedMap.TryGetValue(bpHex, out var element) && !element.StartsWith(DummyTag))
                    result.Add(element);
            }
        }
        return result.ToArray();
    }

    public static (string[] Alice, string[] Bob) RunProtocol(string[] setA, string[] setB, int n = DefaultN)
    {
        var alice = new PsiSession(setA, n);
        var bob   = new PsiSession(setB, n);

        var cA = alice.Commitment();
        var cB = bob.Commitment();
        alice.ReceiveCommitment(cB);
        bob.ReceiveCommitment(cA);

        var msgA1 = alice.BlindedSet();
        var msgB1 = bob.ProcessBlindedSet(msgA1);
        var msgA2 = alice.ProcessResponse(msgB1);
        bob.ProcessFinal(msgA2);

        return (alice.Intersection(), bob.Intersection());
    }
}

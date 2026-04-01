// PsiSession.cs — SHI-PSI protocol state machine and message types

using System.Numerics;
using System.Text;

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
// SHI-PSI Session (Ed25519-based)
// ================================================================

public class PsiSession
{
    public const int DefaultN = 10;
    private const string DummyTag = "DUMMY_";

    private readonly int _n;
    private readonly string[] _realElements;
    private readonly BigInteger _key;
    private readonly string[] _paddedElements;
    private readonly (BigInteger X, BigInteger Y)[] _blindedPoints;
    private readonly BigInteger _commitNonce;
    private readonly (BigInteger X, BigInteger Y) _myCommitment;
    private readonly Dictionary<string, string> _myBlindedMap = new();

    private (BigInteger X, BigInteger Y)? _theirCommitment;
    private (BigInteger X, BigInteger Y)[]? _theirBlinded;
    private (BigInteger X, BigInteger Y)[]? _myDoubleBlinded;
    private (BigInteger X, BigInteger Y)[]? _theirDoubleBlinded;

    public PsiSession(string[] myElements, int n = DefaultN)
    {
        if (myElements.Length > n)
            throw new ArgumentException($"Set size {myElements.Length} exceeds N={n}");

        _n = n;
        _realElements = (string[])myElements.Clone();
        _key = CryptoUtil.RandomScalar();

        // Phase 0: pad, blind, shuffle
        var padded = new List<string>(myElements);
        while (padded.Count < n)
        {
            var rnd = CryptoUtil.BytesToBigInt(CryptoUtil.GetRandomBytes(32));
            padded.Add(DummyTag + ToBase36(rnd));
        }
        _paddedElements = padded.ToArray();

        var blindedList = new (BigInteger X, BigInteger Y)[n];
        for (int i = 0; i < n; i++)
        {
            var bp = Ed25519.ScalarMul(CryptoUtil.HashToGroup(padded[i]), _key);
            blindedList[i] = bp;
            _myBlindedMap[Ed25519.PointToHex(bp)] = padded[i];
        }
        _blindedPoints = CryptoUtil.SecureShuffle(blindedList);

        _commitNonce = CryptoUtil.RandomScalar();
        _myCommitment = CryptoUtil.Commit(_blindedPoints, _commitNonce);
    }

    public CommitmentMsg Commitment() => new(Ed25519.PointToHex(_myCommitment));

    public void ReceiveCommitment(CommitmentMsg msg)
    {
        _theirCommitment = ParsePoint(msg.Commitment);
    }

    public BlindedSetMsg BlindedSet() => new(
        _blindedPoints.Select(Ed25519.PointToHex).ToArray(),
        CryptoUtil.BigIntToHex(_commitNonce));

    public ProcessBlindedSetResponse ProcessBlindedSet(BlindedSetMsg msg)
    {
        var theirPoints = msg.Points.Select(ParsePoint).ToArray();
        var theirNonce = CryptoUtil.HexToBigInt(msg.Nonce);

        if (!CryptoUtil.VerifyCommit(theirPoints, theirNonce, _theirCommitment!.Value))
            throw new InvalidOperationException("Commitment verification failed");
        if (theirPoints.Length != _n)
            throw new InvalidOperationException($"Expected {_n} points, got {theirPoints.Length}");

        _theirBlinded = theirPoints;

        var doubled = theirPoints.Select(p => Ed25519.ScalarMul(p, _key)).ToArray();
        var proof = ChaumPedersen.Prove(theirPoints, doubled, _key);
        var shuffled = CryptoUtil.SecureShuffle(doubled);
        _theirDoubleBlinded = shuffled;

        return new ProcessBlindedSetResponse(
            doubled.Select(Ed25519.PointToHex).ToArray(),
            shuffled.Select(Ed25519.PointToHex).ToArray(),
            new ProofMsg(CryptoUtil.BigIntToHex(proof.C), CryptoUtil.BigIntToHex(proof.S)),
            _blindedPoints.Select(Ed25519.PointToHex).ToArray(),
            CryptoUtil.BigIntToHex(_commitNonce));
    }

    public ProcessResponseResult ProcessResponse(ProcessBlindedSetResponse msg)
    {
        var theirPoints = msg.MyPoints.Select(ParsePoint).ToArray();
        var theirNonce = CryptoUtil.HexToBigInt(msg.MyNonce);

        if (!CryptoUtil.VerifyCommit(theirPoints, theirNonce, _theirCommitment!.Value))
            throw new InvalidOperationException("Commitment verification failed");
        if (theirPoints.Length != _n)
            throw new InvalidOperationException($"Expected {_n} points, got {theirPoints.Length}");

        var orderedDoubled = msg.OrderedDoubleBlinded.Select(ParsePoint).ToArray();
        var shuffledDoubled = msg.DoubleBlinded.Select(ParsePoint).ToArray();
        var proof = new CpProof(CryptoUtil.HexToBigInt(msg.Proof.C), CryptoUtil.HexToBigInt(msg.Proof.S));

        if (orderedDoubled.Length != _n || shuffledDoubled.Length != _n)
            throw new InvalidOperationException($"Expected {_n} double-blinded points");
        if (!ChaumPedersen.Verify(_blindedPoints, orderedDoubled, proof))
            throw new InvalidOperationException("Consistency proof verification failed");
        if (!CryptoUtil.VerifyShuffleMultiset(orderedDoubled, shuffledDoubled))
            throw new InvalidOperationException("Multiset shuffle verification failed");

        _theirBlinded = theirPoints;
        _myDoubleBlinded = orderedDoubled;

        var theirDoubled = theirPoints.Select(p => Ed25519.ScalarMul(p, _key)).ToArray();
        var myProof = ChaumPedersen.Prove(theirPoints, theirDoubled, _key);
        var myShuffled = CryptoUtil.SecureShuffle(theirDoubled);
        _theirDoubleBlinded = myShuffled;

        return new ProcessResponseResult(
            theirDoubled.Select(Ed25519.PointToHex).ToArray(),
            myShuffled.Select(Ed25519.PointToHex).ToArray(),
            new ProofMsg(CryptoUtil.BigIntToHex(myProof.C), CryptoUtil.BigIntToHex(myProof.S)));
    }

    public void ProcessFinal(ProcessResponseResult msg)
    {
        var orderedDoubled = msg.OrderedDoubleBlinded.Select(ParsePoint).ToArray();
        var shuffledDoubled = msg.DoubleBlinded.Select(ParsePoint).ToArray();
        var proof = new CpProof(CryptoUtil.HexToBigInt(msg.Proof.C), CryptoUtil.HexToBigInt(msg.Proof.S));

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

        var mySet = new HashSet<string>(_myDoubleBlinded.Select(Ed25519.PointToHex));
        var theirHexes = _theirDoubleBlinded.Select(Ed25519.PointToHex).ToArray();
        var matchingHexes = new HashSet<string>(theirHexes.Where(h => mySet.Contains(h)));

        var result = new List<string>();
        for (int i = 0; i < _blindedPoints.Length; i++)
        {
            var dbHex = Ed25519.PointToHex(_myDoubleBlinded[i]);
            if (matchingHexes.Contains(dbHex))
            {
                var bpHex = Ed25519.PointToHex(_blindedPoints[i]);
                if (_myBlindedMap.TryGetValue(bpHex, out var element) && !element.StartsWith(DummyTag))
                    result.Add(element);
            }
        }
        return result.ToArray();
    }

    public static (string[] Alice, string[] Bob) RunProtocol(string[] setA, string[] setB, int n = DefaultN)
    {
        var alice = new PsiSession(setA, n);
        var bob = new PsiSession(setB, n);

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

    private static (BigInteger X, BigInteger Y) ParsePoint(string hex)
    {
        var x = CryptoUtil.HexToBigInt(hex[..64]);
        var y = CryptoUtil.HexToBigInt(hex[64..]);
        return (x, y);
    }

    private static string ToBase36(BigInteger n)
    {
        if (n == 0) return "0";
        const string chars = "0123456789abcdefghijklmnopqrstuvwxyz";
        var sb = new StringBuilder();
        var val = BigInteger.Abs(n);
        while (val > 0)
        {
            sb.Insert(0, chars[(int)(val % 36)]);
            val /= 36;
        }
        return sb.ToString();
    }
}
// ShiPsiTests.cs — xUnit v3 test suite for SHI-PSI protocol

using System.Diagnostics;
using System.Security.Cryptography;
using Xunit;

namespace ShiPsiCs.Tests;

// ================================================================
// Test helpers
// ================================================================

internal static class T
{
    internal static byte[] Sid() => CryptoUtil.GetRandomBytes(16);

    internal static PsiSession Session(string[] elements, byte[] sid, int n = 10) =>
        new(elements, sid, "alice", "bob", n);

    internal static (PsiSession Alice, PsiSession Bob) Pair(
        string[] setA, string[] setB, byte[]? sid = null, int n = 10)
    {
        var s = sid ?? Sid();
        return (new PsiSession(setA, s, "alice", "bob", n),
                new PsiSession(setB, s, "bob", "alice", n));
    }

    internal static FiatShamirContext CpCtx() =>
        new(Sid(), "prover", "verifier",
            Ristretto255.HashToPoint("commit_a"),
            Ristretto255.HashToPoint("commit_b"));
}

// ================================================================
// 1. Ristretto255 primitive tests
// ================================================================

public class Ristretto255Tests
{
    [Fact]
    public void HashToPoint_IsDeterministic()
    {
        var p1 = Ristretto255.HashToPoint("test_element");
        var p2 = Ristretto255.HashToPoint("test_element");

        Assert.True(Ristretto255.PointEquals(p1, p2));
    }

    [Fact]
    public void HashToPoint_DifferentInputsProduceDifferentPoints()
    {
        var p1 = Ristretto255.HashToPoint("alice");
        var p2 = Ristretto255.HashToPoint("bob");

        Assert.False(Ristretto255.PointEquals(p1, p2));
    }

    [Fact]
    public void HashToPoint_ProducesCorrectLength()
    {
        var p = Ristretto255.HashToPoint("anything");

        Assert.Equal(Ristretto255.PointBytes, p.Length);
    }

    [Fact]
    public void HexRoundTrip_PreservesPoint()
    {
        var p = Ristretto255.HashToPoint("round_trip_test");
        var hex = Ristretto255.PointToHex(p);
        var restored = Ristretto255.HexToPoint(hex);

        Assert.True(Ristretto255.PointEquals(p, restored));
    }

    [Fact]
    public void PointToHex_IsLowercase()
    {
        var p = Ristretto255.HashToPoint("hex_case_test");
        var hex = Ristretto255.PointToHex(p);

        Assert.Equal(hex, hex.ToLowerInvariant());
    }

    [Fact]
    public void ScalarMul_IsCommutative()
    {
        var a = Ristretto255.RandomScalar();
        var b = Ristretto255.RandomScalar();
        var h = Ristretto255.HashToPoint("commutativity_test");

        var ab = Ristretto255.ScalarMul(Ristretto255.ScalarMul(h, a), b);
        var ba = Ristretto255.ScalarMul(Ristretto255.ScalarMul(h, b), a);

        Assert.True(Ristretto255.PointEquals(ab, ba));
    }

    [Fact]
    public void RandomScalar_IsNonZero()
    {
        var zero = new byte[Ristretto255.ScalarBytes];
        for (int i = 0; i < 50; i++)
        {
            var s = Ristretto255.RandomScalar();
            Assert.False(CryptographicOperations.FixedTimeEquals(s, zero));
        }
    }

    [Fact]
    public void RandomScalar_ProducesDistinctValues()
    {
        var s1 = Ristretto255.RandomScalar();
        var s2 = Ristretto255.RandomScalar();

        Assert.False(Ristretto255.PointEquals(s1, s2));
    }

    [Fact]
    public void RandomScalar_HasCorrectLength()
    {
        var s = Ristretto255.RandomScalar();

        Assert.Equal(Ristretto255.ScalarBytes, s.Length);
    }

    [Fact]
    public void PointAdd_IsCommutative()
    {
        var p = Ristretto255.HashToPoint("add_p");
        var q = Ristretto255.HashToPoint("add_q");

        var pq = Ristretto255.PointAdd(p, q);
        var qp = Ristretto255.PointAdd(q, p);

        Assert.True(Ristretto255.PointEquals(pq, qp));
    }

    [Fact]
    public void PointEquals_RejectsDifferentLengths()
    {
        var a = new byte[32];
        var b = new byte[16];

        Assert.False(Ristretto255.PointEquals(a, b));
    }

    [Fact]
    public void ScalarSub_ThenAdd_IsIdentity()
    {
        var a = Ristretto255.RandomScalar();
        var b = Ristretto255.RandomScalar();
        var h = Ristretto255.HashToPoint("scalar_sub_test");

        var diff = Ristretto255.ScalarSub(a, b);
        var lhs = Ristretto255.PointAdd(
            Ristretto255.ScalarMul(h, diff),
            Ristretto255.ScalarMul(h, b));
        var rhs = Ristretto255.ScalarMul(h, a);

        Assert.True(Ristretto255.PointEquals(lhs, rhs));
    }

    [Fact]
    public void ScalarMulScalar_MatchesRepeatedScalarMulOnPoint()
    {
        var a = Ristretto255.RandomScalar();
        var b = Ristretto255.RandomScalar();
        var h = Ristretto255.HashToPoint("scalar_mul_scalar_test");

        var product = Ristretto255.ScalarMulScalar(a, b);
        var lhs = Ristretto255.ScalarMul(h, product);
        var rhs = Ristretto255.ScalarMul(Ristretto255.ScalarMul(h, b), a);

        Assert.True(Ristretto255.PointEquals(lhs, rhs));
    }
}

// ================================================================
// 2. CryptoUtil tests
// ================================================================

public class CryptoUtilTests
{
    [Fact]
    public void Commit_VerifyCommit_RoundTrip()
    {
        var elements = new byte[3][];
        for (int i = 0; i < 3; i++)
            elements[i] = Ristretto255.HashToPoint($"elem_{i}");
        var nonce = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements, nonce);

        Assert.True(CryptoUtil.VerifyCommit(elements, nonce, commitment));
    }

    [Fact]
    public void VerifyCommit_RejectsWrongNonce()
    {
        var elements = new byte[][] { Ristretto255.HashToPoint("x") };
        var nonce1 = Ristretto255.RandomScalar();
        var nonce2 = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements, nonce1);

        Assert.False(CryptoUtil.VerifyCommit(elements, nonce2, commitment));
    }

    [Fact]
    public void VerifyCommit_RejectsWrongElements()
    {
        var elements1 = new byte[][] { Ristretto255.HashToPoint("real") };
        var elements2 = new byte[][] { Ristretto255.HashToPoint("fake") };
        var nonce = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements1, nonce);

        Assert.False(CryptoUtil.VerifyCommit(elements2, nonce, commitment));
    }

    [Fact]
    public void VerifyCommit_RejectsDifferentElementCount()
    {
        var elements1 = new byte[][]
        {
            Ristretto255.HashToPoint("a"),
            Ristretto255.HashToPoint("b"),
        };
        var elements2 = new byte[][]
        {
            Ristretto255.HashToPoint("a"),
            Ristretto255.HashToPoint("b"),
            Ristretto255.HashToPoint("c"),
        };
        var nonce = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements1, nonce);

        Assert.False(CryptoUtil.VerifyCommit(elements2, nonce, commitment));
    }

    [Fact]
    public void Commit_DifferentOrderProducesSameCommitment()
    {
        var a = Ristretto255.HashToPoint("order_a");
        var b = Ristretto255.HashToPoint("order_b");
        var nonce = Ristretto255.RandomScalar();

        var c1 = CryptoUtil.Commit(new[] { a, b }, nonce);
        var c2 = CryptoUtil.Commit(new[] { b, a }, nonce);

        Assert.True(Ristretto255.PointEquals(c1, c2));
    }

    [Fact]
    public void SecureShuffle_PreservesAllElements()
    {
        var input = new[] { "a", "b", "c", "d", "e" };
        var shuffled = CryptoUtil.SecureShuffle(input);

        Assert.Equal(input.Length, shuffled.Length);
        Assert.Equal(input.OrderBy(x => x), shuffled.OrderBy(x => x));
    }

    [Fact]
    public void SecureShuffle_DoesNotModifyOriginal()
    {
        var input = new[] { "x", "y", "z" };
        var original = (string[])input.Clone();
        _ = CryptoUtil.SecureShuffle(input);
        Assert.Equal(original, input);
    }

    [Fact]
    public void SecureShuffle_SingleElementReturnsSameElement()
    {
        var shuffled = CryptoUtil.SecureShuffle(new[] { "only" });
        Assert.Single(shuffled);
        Assert.Equal("only", shuffled[0]);
    }

    [Fact]
    public void SecureShuffle_EmptyArrayReturnsEmpty()
    {
        Assert.Empty(CryptoUtil.SecureShuffle(Array.Empty<string>()));
    }

    [Fact]
    public void Transcript_IsDeterministic()
    {
        byte[] Hash()
        {
            using var t = new Transcript();
            t.Append("a").Append("b").Append("c");
            return t.Finalize();
        }
        Assert.Equal(Hash(), Hash());
    }

    [Fact]
    public void Transcript_DifferentOrderProducesDifferentResults()
    {
        byte[] h1, h2;
        using (var t = new Transcript()) { t.Append("a").Append("b"); h1 = t.Finalize(); }
        using (var t = new Transcript()) { t.Append("b").Append("a"); h2 = t.Finalize(); }
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void Transcript_Finalize_ProducesScalarLength()
    {
        using var t = new Transcript();
        t.Append("test").Append(42);
        Assert.Equal(Ristretto255.ScalarBytes, t.Finalize().Length);
    }

    [Fact]
    public void Transcript_AcceptsByteArraysStringsAndInts()
    {
        var point = Ristretto255.HashToPoint("test");
        using var t = new Transcript();
        t.Append("prefix").Append(point).Append(42);
        Assert.Equal(Ristretto255.ScalarBytes, t.Finalize().Length);
    }

    [Fact]
    public void Transcript_LengthPrefixing_PreventsCollision()
    {
        byte[] h1, h2;
        using (var t = new Transcript()) { t.Append("ab").Append("c"); h1 = t.Finalize(); }
        using (var t = new Transcript()) { t.Append("a").Append("bc"); h2 = t.Finalize(); }
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void GetRandomBytes_ProducesCorrectLength()
    {
        Assert.Equal(32, CryptoUtil.GetRandomBytes(32).Length);
    }

    [Fact]
    public void CanonicalOrder_IsDeterministic()
    {
        var a = Ristretto255.HashToPoint("canon_a");
        var b = Ristretto255.HashToPoint("canon_b");

        var (f1, s1) = CryptoUtil.CanonicalOrder(a, b);
        var (f2, s2) = CryptoUtil.CanonicalOrder(b, a);

        Assert.True(Ristretto255.PointEquals(f1, f2));
        Assert.True(Ristretto255.PointEquals(s1, s2));
    }

    [Fact]
    public void CanonicalOrder_IdenticalInputs()
    {
        var a = Ristretto255.HashToPoint("same");
        var (f, s) = CryptoUtil.CanonicalOrder(a, (byte[])a.Clone());
        Assert.True(Ristretto255.PointEquals(f, s));
    }
}

// ================================================================
// 3. Chaum-Pedersen proof tests
// ================================================================

public class ChaumPedersenTests
{
    [Fact]
    public void Prove_Verify_HonestExecution()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        var inputs = new byte[5][];
        var outputs = new byte[5][];
        for (int i = 0; i < 5; i++)
        {
            inputs[i] = Ristretto255.HashToPoint($"cp_input_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], k);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);
        Assert.True(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Verify_RejectsWrongKey()
    {
        var k = Ristretto255.RandomScalar();
        var kWrong = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        var inputs = new byte[3][];
        var outputs = new byte[3][];
        for (int i = 0; i < 3; i++)
        {
            inputs[i] = Ristretto255.HashToPoint($"wrong_key_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], k);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, kWrong, ctx);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Verify_RejectsTamperedOutput()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        var inputs = new byte[4][];
        var outputs = new byte[4][];
        for (int i = 0; i < 4; i++)
        {
            inputs[i] = Ristretto255.HashToPoint($"tamper_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], k);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);

        var tampered = (byte[][])outputs.Clone();
        tampered[1] = Ristretto255.HashToPoint("injected_point");

        Assert.False(ChaumPedersen.Verify(inputs, tampered, proof, ctx));
    }

    [Fact]
    public void Verify_RejectsSwappedInputOutputPair()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        var inputs = new byte[3][];
        var outputs = new byte[3][];
        for (int i = 0; i < 3; i++)
        {
            inputs[i] = Ristretto255.HashToPoint($"swap_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], k);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);

        var swapped = (byte[][])outputs.Clone();
        (swapped[0], swapped[2]) = (swapped[2], swapped[0]);

        Assert.False(ChaumPedersen.Verify(inputs, swapped, proof, ctx));
    }

    [Fact]
    public void Prove_Verify_SingleElement()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        var inputs = new[] { Ristretto255.HashToPoint("single") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);
        Assert.True(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Prove_Verify_LargeSet()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        int n = 20;
        var inputs = new byte[n][];
        var outputs = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            inputs[i] = Ristretto255.HashToPoint($"large_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], k);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);
        Assert.True(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Verify_RejectsMixedKeys()
    {
        var k1 = Ristretto255.RandomScalar();
        var k2 = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        var inputs = new byte[4][];
        var outputs = new byte[4][];
        for (int i = 0; i < 4; i++)
        {
            inputs[i] = Ristretto255.HashToPoint($"mixed_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], i < 2 ? k1 : k2);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, k1, ctx);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Proof_ContainsNonNullFields()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.CpCtx();
        var inputs = new[] { Ristretto255.HashToPoint("nonnull") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);

        Assert.NotNull(proof.C);
        Assert.NotNull(proof.S);
        Assert.Equal(Ristretto255.ScalarBytes, proof.C.Length);
        Assert.Equal(Ristretto255.ScalarBytes, proof.S.Length);
    }

    [Fact]
    public void Verify_RejectsDifferentSid()
    {
        var k = Ristretto255.RandomScalar();
        var inputs = new[] { Ristretto255.HashToPoint("sid_test") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var ca = Ristretto255.HashToPoint("ca");
        var cb = Ristretto255.HashToPoint("cb");
        var ctx1 = new FiatShamirContext(T.Sid(), "prover", "verifier", ca, cb);
        var ctx2 = new FiatShamirContext(T.Sid(), "prover", "verifier", ca, cb);

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx1);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx2));
    }

    [Fact]
    public void Verify_RejectsSwappedProverVerifier()
    {
        var k = Ristretto255.RandomScalar();
        var inputs = new[] { Ristretto255.HashToPoint("role_test") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var sid = T.Sid();
        var ca = Ristretto255.HashToPoint("ca");
        var cb = Ristretto255.HashToPoint("cb");
        var proveCtx = new FiatShamirContext(sid, "alice", "bob", ca, cb);
        var wrongCtx = new FiatShamirContext(sid, "bob", "alice", ca, cb);

        var proof = ChaumPedersen.Prove(inputs, outputs, k, proveCtx);

        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, wrongCtx));
        Assert.True(ChaumPedersen.Verify(inputs, outputs, proof, proveCtx));
    }

    [Fact]
    public void Verify_RejectsDifferentCommitments()
    {
        var k = Ristretto255.RandomScalar();
        var inputs = new[] { Ristretto255.HashToPoint("commit_test") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var sid = T.Sid();
        var ctx1 = new FiatShamirContext(sid, "p", "v",
            Ristretto255.HashToPoint("ca"), Ristretto255.HashToPoint("cb"));
        var ctx2 = new FiatShamirContext(sid, "p", "v",
            Ristretto255.HashToPoint("ca"), Ristretto255.HashToPoint("DIFFERENT"));

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx1);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx2));
    }
}

// ================================================================
// 4. Protocol correctness tests (via RunProtocol)
// ================================================================

public class PsiProtocolCorrectnessTests
{
    [Fact]
    public void BasicIntersection()
    {
        var (alice, bob) = PsiSession.RunProtocol(
            ["apple", "banana", "cherry"],
            ["banana", "date", "cherry", "elderberry"], 10);
        var expected = new[] { "banana", "cherry" };
        Assert.Equal(expected, alice.OrderBy(x => x));
        Assert.Equal(expected, bob.OrderBy(x => x));
    }

    [Fact]
    public void NoOverlap()
    {
        var (alice, bob) = PsiSession.RunProtocol(["a", "b", "c"], ["d", "e", "f"], 10);
        Assert.Empty(alice);
        Assert.Empty(bob);
    }

    [Fact]
    public void FullOverlap()
    {
        var (alice, bob) = PsiSession.RunProtocol(["x", "y", "z"], ["x", "y", "z"], 10);
        var expected = new[] { "x", "y", "z" };
        Assert.Equal(expected, alice.OrderBy(x => x));
        Assert.Equal(expected, bob.OrderBy(x => x));
    }

    [Fact]
    public void DifferentSetSizes()
    {
        var (alice, bob) = PsiSession.RunProtocol(
            ["only_one"], ["only_one", "b", "c", "d", "e", "f", "g", "h"], 10);
        Assert.Equal(["only_one"], alice);
        Assert.Equal(["only_one"], bob);
    }

    [Fact] public void SingleElementMatch()   { var (a, b) = PsiSession.RunProtocol(["x"], ["x"], 10); Assert.Equal(["x"], a); Assert.Equal(["x"], b); }
    [Fact] public void SingleElementNoMatch()  { var (a, b) = PsiSession.RunProtocol(["x"], ["y"], 10); Assert.Empty(a); Assert.Empty(b); }
    [Fact] public void BothSetsEmpty()         { var (a, b) = PsiSession.RunProtocol([], [], 10); Assert.Empty(a); Assert.Empty(b); }
    [Fact] public void OneSideEmpty()          { var (a, b) = PsiSession.RunProtocol([], ["a", "b", "c"], 10); Assert.Empty(a); Assert.Empty(b); }

    [Fact]
    public void MaxCapacity_AllMatch()
    {
        var items = Enumerable.Range(0, 10).Select(i => $"item_{i}").ToArray();
        var (alice, bob) = PsiSession.RunProtocol(items, items, 10);
        Assert.Equal(items.OrderBy(x => x), alice.OrderBy(x => x));
        Assert.Equal(items.OrderBy(x => x), bob.OrderBy(x => x));
    }

    [Fact]
    public void MaxCapacity_NoMatch()
    {
        var setA = Enumerable.Range(0, 10).Select(i => $"a_{i}").ToArray();
        var setB = Enumerable.Range(0, 10).Select(i => $"b_{i}").ToArray();
        var (alice, bob) = PsiSession.RunProtocol(setA, setB, 10);
        Assert.Empty(alice);
        Assert.Empty(bob);
    }

    [Fact]
    public void MaxCapacity_PartialMatch()
    {
        var setA = Enumerable.Range(0, 10).Select(i => $"item_{i}").ToArray();
        var setB = Enumerable.Range(5, 10).Select(i => $"item_{i}").ToArray();
        var (alice, bob) = PsiSession.RunProtocol(setA, setB, 10);

        var expected = Enumerable.Range(5, 5).Select(i => $"item_{i}").OrderBy(x => x).ToArray();
        Assert.Equal(expected, alice.OrderBy(x => x));
        Assert.Equal(expected, bob.OrderBy(x => x));
    }

    [Fact] public void SmallN()
    { 
        var (a, b) = PsiSession.RunProtocol(["a"], ["a", "b"], 2);
        Assert.Equal(["a"], a);
        Assert.Equal(["a"], b); 
    }

    [Fact] public void N_Equals_1()
    { 
        var (a, b) = PsiSession.RunProtocol(["shared"], ["shared"], 1);
        Assert.Equal(["shared"], a);
        Assert.Equal(["shared"], b);
    }
    
    [Fact] public void N_Equals_1_No()
    { 
        var (a, b) = PsiSession.RunProtocol(["left"], ["right"], 1);
        Assert.Empty(a);
        Assert.Empty(b);
    }
    
    [Fact] public void LargerN()
    { 
        var (a, b) = PsiSession.RunProtocol(["a", "b"], ["b", "c"], 50); 
        Assert.Equal(["b"], a); 
        Assert.Equal(["b"], b);
    }

    [Fact]
    public void ProtocolIsSymmetric()
    {
        var (r1a, r1b) = PsiSession.RunProtocol(["1", "2", "3"], ["2", "3", "4"], 10);
        var (r2a, r2b) = PsiSession.RunProtocol(["2", "3", "4"], ["1", "2", "3"], 10);

        var expected = new[] { "2", "3" };
        Assert.Equal(expected, r1a.OrderBy(x => x));
        Assert.Equal(expected, r1b.OrderBy(x => x));
        Assert.Equal(expected, r2a.OrderBy(x => x));
        Assert.Equal(expected, r2b.OrderBy(x => x));
    }

    [Fact]
    public void RepeatedExecutions_ProduceConsistentResults()
    {
        for (int i = 0; i < 10; i++)
        {
            var (a, b) = PsiSession.RunProtocol(["stable", "test"], ["test", "other"], 10);
            Assert.Equal(["test"], a);
            Assert.Equal(["test"], b);
        }
    }

    [Theory]
    [InlineData("hello world")]
    [InlineData("")]
    [InlineData("emoji🔑")]
    [InlineData("日本語")]
    [InlineData("a string with spaces and CAPS")]
    public void ArbitraryStringElementsWork(string element)
    {
        var (a, b) = PsiSession.RunProtocol([element], [element], 5);
        Assert.Equal([element], a);
        Assert.Equal([element], b);
    }
}

// ================================================================
// 5. Step-by-step protocol path tests
// ================================================================

public class PsiProtocolStepByStepTests
{
    [Fact]
    public void FullProtocol_StepByStep()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["apple", "banana"], sid, "alice", "bob", 5);
        var bob = new PsiSession(["banana", "cherry"], sid, "bob", "alice", 5);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());
        var aliceFinal = alice.ProcessResponse(bobResponse);
        bob.ProcessFinal(aliceFinal);

        Assert.Equal(["banana"], alice.Intersection());
        Assert.Equal(["banana"], bob.Intersection());
    }

    [Fact]
    public void StepByStep_NoOverlap()
    {
        var (alice, bob) = T.Pair(["a"], ["b"], n: 5);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bobResp = bob.ProcessBlindedSet(alice.BlindedSet());
        var aliceFinal = alice.ProcessResponse(bobResp);
        bob.ProcessFinal(aliceFinal);

        Assert.Empty(alice.Intersection());
        Assert.Empty(bob.Intersection());
    }

    [Fact]
    public void StepByStep_MatchesRunProtocol()
    {
        var setA = new[] { "p", "q", "r" };
        var setB = new[] { "q", "r", "s" };

        var (binAlice, binBob) = PsiSession.RunProtocol(setA, setB, 10);

        var (alice, bob) = T.Pair(setA, setB, n: 10);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());
        bob.ProcessFinal(alice.ProcessResponse(bob.ProcessBlindedSet(alice.BlindedSet())));

        var expected = new[] { "q", "r" };
        Assert.Equal(expected, binAlice.OrderBy(x => x));
        Assert.Equal(expected, alice.Intersection().OrderBy(x => x));
        Assert.Equal(expected, binBob.OrderBy(x => x));
        Assert.Equal(expected, bob.Intersection().OrderBy(x => x));
    }

    [Fact]
    public void BlindedSet_HasExactlyNPoints()
    {
        var session = T.Session(["one"], T.Sid(), n: 7);
        Assert.Equal(7, session.BlindedSet().Points.Length);
    }

    [Fact]
    public void Commitment_Is32Bytes()
    {
        var session = T.Session(["test"], T.Sid(), n: 5);
        Assert.Equal(Ristretto255.PointBytes, session.Commitment().Length);
    }

    [Fact]
    public void Commitment_IsStableAcrossCalls()
    {
        var session = T.Session(["test"], T.Sid(), n: 5);
        Assert.True(Ristretto255.PointEquals(session.Commitment(), session.Commitment()));
    }

    [Fact]
    public void BlindedSet_IsStableAcrossCalls()
    {
        var session = T.Session(["test"], T.Sid(), n: 5);
        var bs1 = session.BlindedSet();
        var bs2 = session.BlindedSet();

        Assert.Equal(bs1.Nonce, bs2.Nonce);
        for (int i = 0; i < bs1.Points.Length; i++)
            Assert.True(Ristretto255.PointEquals(bs1.Points[i], bs2.Points[i]));
    }
}

// ================================================================
// 6. PsiSession construction edge cases
// ================================================================

public class PsiSessionEdgeCaseTests
{
    [Fact]
    public void Constructor_ThrowsWhenSetExceedsN()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new PsiSession(["a", "b", "c"], T.Sid(), "a", "b", n: 2));
        Assert.Contains("exceeds N=2", ex.Message);
    }

    [Fact] public void Constructor_ThrowsOnEmptySid()    { Assert.Throws<ArgumentException>(() => new PsiSession(["a"], Array.Empty<byte>(), "a", "b")); }
    [Fact] public void Constructor_ThrowsOnEmptyMyId()   { Assert.Throws<ArgumentException>(() => new PsiSession(["a"], T.Sid(), "", "b")); }
    [Fact] public void Constructor_ThrowsOnEmptyTheirId(){ Assert.Throws<ArgumentException>(() => new PsiSession(["a"], T.Sid(), "a", "")); }

    [Fact]
    public void Intersection_ThrowsBeforeProtocolComplete()
    {
        Assert.Throws<InvalidOperationException>(
            () => T.Session(["a"], T.Sid(), n: 5).Intersection());
    }

    [Fact]
    public void Intersection_ThrowsAfterOnlyCommitmentExchange()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        Assert.Throws<InvalidOperationException>(() => alice.Intersection());
        Assert.Throws<InvalidOperationException>(() => bob.Intersection());
    }

    [Fact]
    public void Constructor_AcceptsExactlyN()
    {
        var session = new PsiSession(["a", "b", "c"], T.Sid(), "a", "b", n: 3);
        Assert.NotNull(session.Commitment());
    }

    [Fact]
    public void Constructor_AcceptsEmptySet()
    {
        Assert.NotNull(T.Session([], T.Sid(), n: 5).Commitment());
    }

    [Fact]
    public void TwoSessionsSameInput_ProduceDifferentCommitments()
    {
        var sid = T.Sid();
        var s1 = T.Session(["a", "b"], sid, n: 5);
        var s2 = T.Session(["a", "b"], sid, n: 5);

        Assert.False(Ristretto255.PointEquals(s1.Commitment(), s2.Commitment()));
    }
}

// ================================================================
// 7. Security / verification failure tests
// ================================================================

public class PsiProtocolSecurityTests
{
    [Fact]
    public void TamperedCommitment_IsRejected()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", 5);
        var bob = new PsiSession(["a"], sid, "bob", "alice", 5);

        alice.ReceiveCommitment(Ristretto255.HashToPoint("fake")); // wrong commitment
        bob.ReceiveCommitment(alice.Commitment());

        var ex = Assert.Throws<InvalidOperationException>(
            () => alice.ProcessResponse(bob.ProcessBlindedSet(alice.BlindedSet())));
        Assert.Contains("Commitment verification failed", ex.Message);
    }

    [Fact]
    public void TamperedBlindedSet_CommitmentMismatch()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bs = alice.BlindedSet();
        var tamperedPoints = (byte[][])bs.Points.Clone();
        tamperedPoints[0] = Ristretto255.HashToPoint("injected");

        var ex = Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(new BlindedSetMsg(tamperedPoints, bs.Nonce)));
        Assert.Contains("Commitment verification failed", ex.Message);
    }

    [Fact]
    public void TamperedDoubleBlindedPoints_ProofRejected()
    {
        var (alice, bob) = T.Pair(["a", "b"], ["a", "c"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());
        var tamperedDb = (byte[][])bobResponse.DoubleBlinded.Clone();
        tamperedDb[0] = Ristretto255.HashToPoint("tampered");

        var ex = Assert.Throws<InvalidOperationException>(
            () => alice.ProcessResponse(bobResponse with { DoubleBlinded = tamperedDb }));
        Assert.Contains("proof verification failed", ex.Message);
    }

    [Fact]
    public void TamperedFinalMessage_ProofRejected()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var aliceFinal = alice.ProcessResponse(bob.ProcessBlindedSet(alice.BlindedSet()));
        var tamperedDb = (byte[][])aliceFinal.DoubleBlinded.Clone();
        tamperedDb[0] = Ristretto255.HashToPoint("evil");

        var ex = Assert.Throws<InvalidOperationException>(
            () => bob.ProcessFinal(aliceFinal with { DoubleBlinded = tamperedDb }));
        Assert.Contains("proof verification failed", ex.Message);
    }

    [Fact]
    public void WrongPointCount_InDoubleBlinded_IsRejected()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());
        var ex = Assert.Throws<InvalidOperationException>(
            () => alice.ProcessResponse(
                bobResponse with { DoubleBlinded = bobResponse.DoubleBlinded.Take(3).ToArray() }));
        Assert.Contains("Expected 5 double-blinded", ex.Message);
    }

    [Fact]
    public void WrongPointCount_InBlindedSet_IsRejected()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bs = alice.BlindedSet();
        var ex = Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(new BlindedSetMsg(bs.Points.Take(3).ToArray(), bs.Nonce)));
        Assert.Contains("Expected 5 points, got 3", ex.Message);
    }

    [Fact]
    public void MismatchedN_BetweenParties_Fails()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", 5);
        var bob = new PsiSession(["a"], sid, "bob", "alice", 10);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(alice.BlindedSet()));
    }

    [Fact]
    public void ReplayedNonce_WithDifferentPoints_Fails()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bs = alice.BlindedSet();
        var fakePoints = Enumerable.Range(0, 5)
            .Select(i => Ristretto255.HashToPoint($"fake_{i}")).ToArray();

        Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(new BlindedSetMsg(fakePoints, bs.Nonce)));
    }

    [Fact]
    public void SwappedProof_BetweenSessions_IsRejected()
    {
        var sid1 = T.Sid();
        var alice = new PsiSession(["x", "y"], sid1, "alice", "bob", 5);
        var bob = new PsiSession(["x", "z"], sid1, "bob", "alice", 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());
        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());

        var sid2 = T.Sid();
        var eve = new PsiSession(["a"], sid2, "eve", "frank", 5);
        var frank = new PsiSession(["a"], sid2, "frank", "eve", 5);
        eve.ReceiveCommitment(frank.Commitment());
        frank.ReceiveCommitment(eve.Commitment());
        var frankResponse = frank.ProcessBlindedSet(eve.BlindedSet());

        Assert.Throws<InvalidOperationException>(
            () => alice.ProcessResponse(bobResponse with { Proof = frankResponse.Proof }));
    }
}

// ================================================================
// 8. Duplicate element behavior
// ================================================================

public class PsiDuplicateElementTests
{
    [Fact] public void Dedup_InOneSet()   { var (a, b) = PsiSession.RunProtocol(["a", "a", "b"], ["a", "c"], 5); Assert.Equal(["a"], a); Assert.Equal(["a"], b); }
    [Fact] public void Dedup_InBothSets() { var (a, b) = PsiSession.RunProtocol(["x", "x"], ["x", "x"], 5); Assert.Equal(["x"], a); Assert.Equal(["x"], b); }
    [Fact] public void Dedup_FitsSmallN() { var (a, b) = PsiSession.RunProtocol(["a", "a", "a"], ["a"], 1); Assert.Equal(["a"], a); Assert.Equal(["a"], b); }

    [Fact]
    public void Dedup_ExceedingNAfterDedup_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => new PsiSession(["a", "b", "a", "c"], T.Sid(), "a", "b", n: 2));
    }

    [Fact]
    public void Dedup_ExactFitAfterDedup()
    {
        var session = new PsiSession(["a", "b", "a"], T.Sid(), "a", "b", n: 2);
        Assert.NotNull(session.Commitment());
    }
}

// ================================================================
// 9. State-machine guard tests
// ================================================================

public class PsiStateMachineGuardTests
{
    [Fact]
    public void ProcessBlindedSet_WithoutReceiveCommitment_GivesClearError()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        var ex = Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(alice.BlindedSet()));
        Assert.Contains("ReceiveCommitment must be called", ex.Message);
    }

    [Fact]
    public void ProcessResponse_WithoutReceiveCommitment_GivesClearError()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", 5);
        var bob = new PsiSession(["a"], sid, "bob", "alice", 5);

        bob.ReceiveCommitment(alice.Commitment());
        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());

        var freshAlice = new PsiSession(["a"], sid, "alice", "bob", 5);
        var ex = Assert.Throws<InvalidOperationException>(
            () => freshAlice.ProcessResponse(bobResponse));
        Assert.Contains("ReceiveCommitment must be called", ex.Message);
    }
}

// ================================================================
// 10. Size-hiding property tests
// ================================================================

public class PsiSizeHidingTests
{
    [Fact]
    public void AllBlindedSets_HaveSameSize_RegardlessOfInputSize()
    {
        var sid = T.Sid();
        for (int count = 0; count <= 10; count++)
        {
            var elements = Enumerable.Range(0, count).Select(i => $"elem_{i}").ToArray();
            Assert.Equal(10, T.Session(elements, sid, n: 10).BlindedSet().Points.Length);
        }
    }

    [Fact]
    public void CommitmentsAreSameSize_ForDifferentInputSizes()
    {
        var sid = T.Sid();
        Assert.Equal(
            T.Session(["a"], sid, n: 10).Commitment().Length,
            T.Session(Enumerable.Range(0, 10).Select(i => $"x_{i}").ToArray(), sid, n: 10).Commitment().Length);
    }

    [Fact]
    public void Response_HasFixedPointCount()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", 10);
        var bob = new PsiSession(["a", "b", "c", "d", "e"], sid, "bob", "alice", 10);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var response = bob.ProcessBlindedSet(alice.BlindedSet());
        Assert.Equal(10, response.DoubleBlinded.Length);
        Assert.Equal(10, response.MyPoints.Length);
    }
}

// ================================================================
// 11. Fiat-Shamir transcript binding tests (Section 3.4)
// ================================================================

public class PsiFiatShamirBindingTests
{
    [Fact]
    public void CrossSessionReplay_IsRejected()
    {
        var sid1 = T.Sid();
        var alice1 = new PsiSession(["a"], sid1, "alice", "bob", 5);
        var bob1 = new PsiSession(["a"], sid1, "bob", "alice", 5);
        alice1.ReceiveCommitment(bob1.Commitment());
        bob1.ReceiveCommitment(alice1.Commitment());
        var bob1Response = bob1.ProcessBlindedSet(alice1.BlindedSet());

        var sid2 = T.Sid();
        var alice2 = new PsiSession(["a"], sid2, "alice", "bob", 5);
        var bob2 = new PsiSession(["a"], sid2, "bob", "alice", 5);
        alice2.ReceiveCommitment(bob2.Commitment());
        bob2.ReceiveCommitment(alice2.Commitment());

        Assert.Throws<InvalidOperationException>(
            () => alice2.ProcessResponse(bob1Response));
    }

    [Fact]
    public void CrossPartyReplay_IsRejected()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", 5);
        var bob = new PsiSession(["a"], sid, "bob", "alice", 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());
        var aliceFinal = alice.ProcessResponse(bobResponse);

        // Splice Bob's proof (prover=bob) into Alice's final message
        Assert.Throws<InvalidOperationException>(
            () => bob.ProcessFinal(aliceFinal with { Proof = bobResponse.Proof }));
    }

    [Fact]
    public void SameElements_DifferentPartyIds_Works()
    {
        var sid = T.Sid();
        var (a, b) = PsiSession.RunProtocol(
            ["shared"], ["shared"], 5,
            sid: sid, idA: "device_A_abc123", idB: "device_B_xyz789");
        Assert.Equal(["shared"], a);
        Assert.Equal(["shared"], b);
    }

    [Fact]
    public void ExplicitSid_ThreadsThroughProtocol()
    {
        var sid = CryptoUtil.GetRandomBytes(16);
        var (a, b) = PsiSession.RunProtocol(["x", "y"], ["y", "z"], 5, sid: sid);
        Assert.Equal(["y"], a);
        Assert.Equal(["y"], b);
    }
}

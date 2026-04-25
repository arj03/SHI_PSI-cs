using Xunit;

namespace ShiPsiCs.Tests;

// ================================================================
// Test helpers
// ================================================================

internal static class T
{
    internal static byte[] Sid() => CryptoUtil.GetRandomBytes(16);

    internal static PsiSession Session(string[] elements, byte[] sid, int n = 10) =>
        new(elements, sid, "alice", "bob", PartyRole.Initiator, n);

    internal static (PsiSession Alice, PsiSession Bob) Pair(
        string[] setA, string[] setB, byte[]? sid = null, int n = 10)
    {
        var s = sid ?? Sid();
        return (new PsiSession(setA, s, "alice", "bob", PartyRole.Initiator, n),
                new PsiSession(setB, s, "bob", "alice", PartyRole.Responder, n));
    }

    internal static FiatShamirContext ProofCtx() =>
        new(Sid(), "prover", "verifier",
            Ristretto255.HashToPoint("test", "commit_a"),
            Ristretto255.HashToPoint("test", "commit_b"));
}

// ================================================================
// 1. CryptoUtil tests
// ================================================================

public class CryptoUtilTests
{
    [Fact]
    public void Commit_VerifyCommit_RoundTrip()
    {
        var elements = new byte[3][];
        for (int i = 0; i < 3; i++)
            elements[i] = Ristretto255.HashToPoint("test",$"elem_{i}");
        var nonce = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements, nonce);

        Assert.True(CryptoUtil.VerifyCommit(elements, nonce, commitment));
    }

    [Fact]
    public void VerifyCommit_RejectsWrongNonce()
    {
        var elements = new byte[][] { Ristretto255.HashToPoint("test","x") };
        var nonce1 = Ristretto255.RandomScalar();
        var nonce2 = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements, nonce1);

        Assert.False(CryptoUtil.VerifyCommit(elements, nonce2, commitment));
    }

    [Fact]
    public void VerifyCommit_RejectsWrongElements()
    {
        var elements1 = new byte[][] { Ristretto255.HashToPoint("test","real") };
        var elements2 = new byte[][] { Ristretto255.HashToPoint("test","fake") };
        var nonce = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements1, nonce);

        Assert.False(CryptoUtil.VerifyCommit(elements2, nonce, commitment));
    }

    [Fact]
    public void VerifyCommit_RejectsDifferentElementCount()
    {
        var elements1 = new byte[][]
        {
            Ristretto255.HashToPoint("test","a"),
            Ristretto255.HashToPoint("test","b"),
        };
        var elements2 = new byte[][]
        {
            Ristretto255.HashToPoint("test","a"),
            Ristretto255.HashToPoint("test","b"),
            Ristretto255.HashToPoint("test","c"),
        };
        var nonce = Ristretto255.RandomScalar();

        var commitment = CryptoUtil.Commit(elements1, nonce);

        Assert.False(CryptoUtil.VerifyCommit(elements2, nonce, commitment));
    }

    [Fact]
    public void Commit_DifferentOrderProducesSameCommitment()
    {
        var a = Ristretto255.HashToPoint("test","order_a");
        var b = Ristretto255.HashToPoint("test","order_b");
        var nonce = Ristretto255.RandomScalar();

        var c1 = CryptoUtil.Commit(new[] { a, b }, nonce);
        var c2 = CryptoUtil.Commit(new[] { b, a }, nonce);

        Assert.True(Ristretto255.PointEquals(c1, c2));
    }
}

// ================================================================
// 2. Chaum-Pedersen proof tests
// ================================================================

public class ChaumPedersenTests
{
    [Fact]
    public void Prove_Verify_HonestExecution()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.ProofCtx();
        var inputs = new byte[5][];
        var outputs = new byte[5][];
        for (int i = 0; i < 5; i++)
        {
            inputs[i] = Ristretto255.HashToPoint("test",$"cp_input_{i}");
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
        var ctx = T.ProofCtx();
        var inputs = new byte[3][];
        var outputs = new byte[3][];
        for (int i = 0; i < 3; i++)
        {
            inputs[i] = Ristretto255.HashToPoint("test",$"wrong_key_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], k);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, kWrong, ctx);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Verify_RejectsTamperedOutput()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.ProofCtx();
        var inputs = new byte[4][];
        var outputs = new byte[4][];
        for (int i = 0; i < 4; i++)
        {
            inputs[i] = Ristretto255.HashToPoint("test",$"tamper_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], k);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);

        var tampered = (byte[][])outputs.Clone();
        tampered[1] = Ristretto255.HashToPoint("test","injected_point");

        Assert.False(ChaumPedersen.Verify(inputs, tampered, proof, ctx));
    }

    [Fact]
    public void Verify_RejectsSwappedInputOutputPair()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.ProofCtx();
        var inputs = new byte[3][];
        var outputs = new byte[3][];
        for (int i = 0; i < 3; i++)
        {
            inputs[i] = Ristretto255.HashToPoint("test",$"swap_{i}");
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
        var ctx = T.ProofCtx();
        var inputs = new[] { Ristretto255.HashToPoint("test","single") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx);
        Assert.True(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Prove_Verify_LargeSet()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.ProofCtx();
        int n = 20;
        var inputs = new byte[n][];
        var outputs = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            inputs[i] = Ristretto255.HashToPoint("test",$"large_{i}");
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
        var ctx = T.ProofCtx();
        var inputs = new byte[4][];
        var outputs = new byte[4][];
        for (int i = 0; i < 4; i++)
        {
            inputs[i] = Ristretto255.HashToPoint("test",$"mixed_{i}");
            outputs[i] = Ristretto255.ScalarMul(inputs[i], i < 2 ? k1 : k2);
        }

        var proof = ChaumPedersen.Prove(inputs, outputs, k1, ctx);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx));
    }

    [Fact]
    public void Proof_ContainsNonNullFields()
    {
        var k = Ristretto255.RandomScalar();
        var ctx = T.ProofCtx();
        var inputs = new[] { Ristretto255.HashToPoint("test","nonnull") };
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
        var inputs = new[] { Ristretto255.HashToPoint("test","sid_test") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var ca = Ristretto255.HashToPoint("test","ca");
        var cb = Ristretto255.HashToPoint("test","cb");
        var ctx1 = new FiatShamirContext(T.Sid(), "prover", "verifier", ca, cb);
        var ctx2 = new FiatShamirContext(T.Sid(), "prover", "verifier", ca, cb);

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx1);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx2));
    }

    [Fact]
    public void Verify_RejectsSwappedProverVerifier()
    {
        var k = Ristretto255.RandomScalar();
        var inputs = new[] { Ristretto255.HashToPoint("test","role_test") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var sid = T.Sid();
        var ca = Ristretto255.HashToPoint("test","ca");
        var cb = Ristretto255.HashToPoint("test","cb");
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
        var inputs = new[] { Ristretto255.HashToPoint("test","commit_test") };
        var outputs = new[] { Ristretto255.ScalarMul(inputs[0], k) };

        var sid = T.Sid();
        var ctx1 = new FiatShamirContext(sid, "p", "v",
            Ristretto255.HashToPoint("test","ca"), Ristretto255.HashToPoint("test","cb"));
        var ctx2 = new FiatShamirContext(sid, "p", "v",
            Ristretto255.HashToPoint("test","ca"), Ristretto255.HashToPoint("test","DIFFERENT"));

        var proof = ChaumPedersen.Prove(inputs, outputs, k, ctx1);
        Assert.False(ChaumPedersen.Verify(inputs, outputs, proof, ctx2));
    }
}

// ================================================================
// 3. Protocol correctness tests (via RunProtocol)
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

    [Fact] public void SmallN()
    { 
        var (a, b) = PsiSession.RunProtocol(["a"], ["a", "b"], 2);
        Assert.Equal(["a"], a);
        Assert.Equal(["a"], b); 
    }
   
    [Fact] public void LargerN()
    { 
        var (a, b) = PsiSession.RunProtocol(["a", "b"], ["b", "c"], 500); 
        Assert.Equal(["b"], a); 
        Assert.Equal(["b"], b);
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

    [Fact]
    public void BothSetsEmpty_ProducesEmptyIntersection()
    {
        var (a, b) = PsiSession.RunProtocol([], [], 5);
        Assert.Empty(a);
        Assert.Empty(b);
    }

    [Fact]
    public void OneSetEmpty_ProducesEmptyIntersection()
    {
        var (a, b) = PsiSession.RunProtocol([], ["x", "y"], 5);
        Assert.Empty(a);
        Assert.Empty(b);
    }

    [Fact]
    public void FullOverlap_ReturnsAllElements()
    {
        var elements = new[] { "alpha", "beta", "gamma", "delta" };
        var (a, b) = PsiSession.RunProtocol(elements, elements, 10);
        Assert.Equal(elements.OrderBy(x => x), a.OrderBy(x => x));
        Assert.Equal(elements.OrderBy(x => x), b.OrderBy(x => x));
    }

    [Fact]
    public void DuplicateInputs_AreSilentlyDeduplicated()
    {
        // Spec is set-based; duplicates in the input array should not cause
        // failures or produce duplicate matches.
        var (a, b) = PsiSession.RunProtocol(["x", "x", "y"], ["x", "y", "y", "z"], 10);
        Assert.Equal(new[] { "x", "y" }, a.OrderBy(s => s));
        Assert.Equal(new[] { "x", "y" }, b.OrderBy(s => s));
    }
}

// ================================================================
// 4. Step-by-step protocol path tests
// ================================================================

public class PsiProtocolStepByStepTests
{
    [Fact]
    public void FullProtocol_StepByStep()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["apple", "banana"], sid, "alice", "bob", PartyRole.Initiator, 5);
        var bob = new PsiSession(["banana", "cherry"], sid, "bob", "alice", PartyRole.Responder, 5);

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
// 5. PsiSession construction edge cases
// ================================================================

public class PsiSessionEdgeCaseTests
{
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
    public void TwoSessionsSameInput_ProduceDifferentCommitments()
    {
        var sid = T.Sid();
        var s1 = T.Session(["a", "b"], sid, n: 5);
        var s2 = T.Session(["a", "b"], sid, n: 5);

        Assert.False(Ristretto255.PointEquals(s1.Commitment(), s2.Commitment()));
    }

    [Fact]
    public void N_Zero_RejectedAtConstruction()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => new PsiSession([], T.Sid(), "alice", "bob", PartyRole.Initiator, 0));
        Assert.Contains("N must be at least 1", ex.Message);
    }
}

// ================================================================
// 5b. Role / phase state-machine tests
// ================================================================

public class PsiRolePhaseTests
{
    [Fact]
    public void Initiator_CannotCall_ProcessBlindedSet()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());

        var ex = Assert.Throws<InvalidOperationException>(
            () => alice.ProcessBlindedSet(bob.BlindedSet()));
        Assert.Contains("Responder", ex.Message);
    }

    [Fact]
    public void Responder_CannotCall_ProcessResponse()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());
        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());

        var ex = Assert.Throws<InvalidOperationException>(
            () => bob.ProcessResponse(bobResponse));
        Assert.Contains("Initiator", ex.Message);
    }

    [Fact]
    public void Initiator_CannotCall_ProcessFinal()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());
        var aliceFinal = alice.ProcessResponse(bob.ProcessBlindedSet(alice.BlindedSet()));

        var ex = Assert.Throws<InvalidOperationException>(
            () => alice.ProcessFinal(aliceFinal));
        Assert.Contains("Responder", ex.Message);
    }

    [Fact]
    public void ProcessBlindedSet_BeforeReceivingCommitment_Fails()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        var ex = Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(alice.BlindedSet()));
        Assert.Contains("CommitmentReceived", ex.Message);
    }

    [Fact]
    public void ReceiveCommitment_Twice_Fails()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        var ex = Assert.Throws<InvalidOperationException>(
            () => alice.ReceiveCommitment(bob.Commitment()));
        Assert.Contains("Created", ex.Message);
    }

    [Fact]
    public void ProcessFinal_BeforeProcessBlindedSet_Fails()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());
        var aliceFinal = alice.ProcessResponse(bob.ProcessBlindedSet(alice.BlindedSet()));

        // Construct a second responder that never called ProcessBlindedSet.
        var fresh = new PsiSession(["a"], T.Sid(), "bob", "alice", PartyRole.Responder, 5);
        fresh.ReceiveCommitment(alice.Commitment());
        var ex = Assert.Throws<InvalidOperationException>(
            () => fresh.ProcessFinal(aliceFinal));
        Assert.Contains("BlindedSetProcessed", ex.Message);
    }

    [Fact]
    public void Phase_Advances_Through_HappyPath()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        Assert.Equal(ProtocolPhase.Created, alice.Phase);
        Assert.Equal(ProtocolPhase.Created, bob.Phase);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());
        Assert.Equal(ProtocolPhase.CommitmentReceived, alice.Phase);
        Assert.Equal(ProtocolPhase.CommitmentReceived, bob.Phase);

        var bobResp = bob.ProcessBlindedSet(alice.BlindedSet());
        Assert.Equal(ProtocolPhase.BlindedSetProcessed, bob.Phase);

        var aliceFinal = alice.ProcessResponse(bobResp);
        Assert.Equal(ProtocolPhase.Complete, alice.Phase);

        bob.ProcessFinal(aliceFinal);
        Assert.Equal(ProtocolPhase.Complete, bob.Phase);
    }

    [Fact]
    public void Phase_NotAdvancedOnVerificationFailure()
    {
        var (alice, bob) = T.Pair(["a"], ["a"], n: 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var bs = alice.BlindedSet();
        var tamperedPoints = (byte[][])bs.Points.Clone();
        tamperedPoints[0] = Ristretto255.HashToPoint("test","injected");

        Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(new BlindedSetMsg(tamperedPoints, bs.Nonce)));
        // Phase must not have advanced.
        Assert.Equal(ProtocolPhase.CommitmentReceived, bob.Phase);
    }
}

// ================================================================
// 6. Security / verification failure tests
// ================================================================

public class PsiProtocolSecurityTests
{
    [Fact]
    public void TamperedCommitment_IsRejected()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", PartyRole.Initiator, 5);
        var bob = new PsiSession(["a"], sid, "bob", "alice", PartyRole.Responder, 5);

        alice.ReceiveCommitment(Ristretto255.HashToPoint("test","fake")); // wrong commitment
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
        tamperedPoints[0] = Ristretto255.HashToPoint("test","injected");

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
        tamperedDb[0] = Ristretto255.HashToPoint("test","tampered");

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
        tamperedDb[0] = Ristretto255.HashToPoint("test","evil");

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
        Assert.Contains("expected 5 points, got 3", ex.Message);
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
        Assert.Contains("expected 5 points, got 3", ex.Message);
    }

    [Fact]
    public void MismatchedN_BetweenParties_Fails()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", PartyRole.Initiator, 5);
        var bob = new PsiSession(["a"], sid, "bob", "alice", PartyRole.Responder, 10);

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
            .Select(i => Ristretto255.HashToPoint("test",$"fake_{i}")).ToArray();

        Assert.Throws<InvalidOperationException>(
            () => bob.ProcessBlindedSet(new BlindedSetMsg(fakePoints, bs.Nonce)));
    }

    [Fact]
    public void SwappedProof_BetweenSessions_IsRejected()
    {
        var sid1 = T.Sid();
        var alice = new PsiSession(["x", "y"], sid1, "alice", "bob", PartyRole.Initiator, 5);
        var bob = new PsiSession(["x", "z"], sid1, "bob", "alice", PartyRole.Responder, 5);
        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());
        var bobResponse = bob.ProcessBlindedSet(alice.BlindedSet());

        var sid2 = T.Sid();
        var eve = new PsiSession(["a"], sid2, "eve", "frank", PartyRole.Initiator, 5);
        var frank = new PsiSession(["a"], sid2, "frank", "eve", PartyRole.Responder, 5);
        eve.ReceiveCommitment(frank.Commitment());
        frank.ReceiveCommitment(eve.Commitment());
        var frankResponse = frank.ProcessBlindedSet(eve.BlindedSet());

        Assert.Throws<InvalidOperationException>(
            () => alice.ProcessResponse(bobResponse with { Proof = frankResponse.Proof }));
    }
}

// ================================================================
// 7. Size-hiding property tests
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
        var alice = new PsiSession(["a"], sid, "alice", "bob", PartyRole.Initiator, 10);
        var bob = new PsiSession(["a", "b", "c", "d", "e"], sid, "bob", "alice", PartyRole.Responder, 10);

        alice.ReceiveCommitment(bob.Commitment());
        bob.ReceiveCommitment(alice.Commitment());

        var response = bob.ProcessBlindedSet(alice.BlindedSet());
        Assert.Equal(10, response.DoubleBlinded.Length);
        Assert.Equal(10, response.MyPoints.Length);
    }
}

// ================================================================
// 8. Fiat-Shamir transcript binding tests (Section 3.4)
// ================================================================

public class PsiFiatShamirBindingTests
{
    [Fact]
    public void CrossSessionReplay_IsRejected()
    {
        var sid1 = T.Sid();
        var alice1 = new PsiSession(["a"], sid1, "alice", "bob", PartyRole.Initiator, 5);
        var bob1 = new PsiSession(["a"], sid1, "bob", "alice", PartyRole.Responder, 5);
        alice1.ReceiveCommitment(bob1.Commitment());
        bob1.ReceiveCommitment(alice1.Commitment());
        var bob1Response = bob1.ProcessBlindedSet(alice1.BlindedSet());

        var sid2 = T.Sid();
        var alice2 = new PsiSession(["a"], sid2, "alice", "bob", PartyRole.Initiator, 5);
        var bob2 = new PsiSession(["a"], sid2, "bob", "alice", PartyRole.Responder, 5);
        alice2.ReceiveCommitment(bob2.Commitment());
        bob2.ReceiveCommitment(alice2.Commitment());

        Assert.Throws<InvalidOperationException>(
            () => alice2.ProcessResponse(bob1Response));
    }

    [Fact]
    public void CrossPartyReplay_IsRejected()
    {
        var sid = T.Sid();
        var alice = new PsiSession(["a"], sid, "alice", "bob", PartyRole.Initiator, 5);
        var bob = new PsiSession(["a"], sid, "bob", "alice", PartyRole.Responder, 5);
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
}
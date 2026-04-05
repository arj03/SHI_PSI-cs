// ShiPsi.cs — Size-Hiding Private Set Intersection Protocol
// WARNING: Prototype. Do not use for production without hardening.

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ShiPsiCs;

// ================================================================
// Ristretto255 via libsodium
// ================================================================

public static partial class Ristretto255
{
    public const int PointBytes  = 32;
    public const int ScalarBytes = 32;

    // ── P/Invoke ─────────────────────────────────────────────────

    [LibraryImport("libsodium")]
    private static partial int crypto_scalarmult_ristretto255(
        Span<byte> q, ReadOnlySpan<byte> n, ReadOnlySpan<byte> p);

    [LibraryImport("libsodium")]
    private static partial int crypto_core_ristretto255_from_hash(
        Span<byte> p, ReadOnlySpan<byte> r);

    [LibraryImport("libsodium")]
    private static partial int crypto_core_ristretto255_add(
        Span<byte> r, ReadOnlySpan<byte> p, ReadOnlySpan<byte> q);

    [LibraryImport("libsodium")]
    private static partial void crypto_core_ristretto255_scalar_reduce(
        Span<byte> r, ReadOnlySpan<byte> s);

    [LibraryImport("libsodium")]
    private static partial void crypto_core_ristretto255_scalar_sub(
        Span<byte> z, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y);

    [LibraryImport("libsodium")]
    private static partial void crypto_core_ristretto255_scalar_mul(
        Span<byte> z, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y);

    // ── EC operations ────────────────────────────────────────────

    public static byte[] ScalarMul(byte[] point, byte[] scalar)
    {
        var q = new byte[PointBytes];
        if (crypto_scalarmult_ristretto255(q, scalar, point) != 0)
            throw new InvalidOperationException("Ristretto255 scalar multiplication failed");
        return q;
    }

    public static byte[] PointAdd(byte[] p, byte[] q)
    {
        var r = new byte[PointBytes];
        if (crypto_core_ristretto255_add(r, p, q) != 0)
            throw new InvalidOperationException("Ristretto255 point addition failed");
        return r;
    }

    public static byte[] HashToPoint(string element)
    {
        Span<byte> h = stackalloc byte[64];
        SHA512.HashData(Encoding.UTF8.GetBytes("h2c|" + element), h);
        var p = new byte[PointBytes];
        crypto_core_ristretto255_from_hash(p, h);
        return p;
    }

    // ── Scalar arithmetic ────────────────────────────────────────

    public static byte[] ScalarReduce64(byte[] s64)
    {
        var r = new byte[ScalarBytes];
        crypto_core_ristretto255_scalar_reduce(r, s64);
        return r;
    }

    public static byte[] ScalarSub(byte[] a, byte[] b)
    {
        var z = new byte[ScalarBytes];
        crypto_core_ristretto255_scalar_sub(z, a, b);
        return z;
    }

    public static byte[] ScalarMulScalar(byte[] a, byte[] b)
    {
        var z = new byte[ScalarBytes];
        crypto_core_ristretto255_scalar_mul(z, a, b);
        return z;
    }

    public static byte[] RandomScalar()
    {
        Span<byte> raw = stackalloc byte[64];
        var r = new byte[ScalarBytes];
        do
        {
            RandomNumberGenerator.Fill(raw);
            crypto_core_ristretto255_scalar_reduce(r, raw);
        }
        while (CryptographicOperations.FixedTimeEquals(r, Zero));
        return r;
    }

    // ── Comparison and encoding helpers ──────────────────────────

    public static bool PointEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    public static string PointToHex(byte[] p) =>
        Convert.ToHexString(p).ToLowerInvariant();

    public static byte[] HexToPoint(string hex) =>
        Convert.FromHexString(hex);

    private static readonly byte[] Zero = new byte[ScalarBytes];
}

// ================================================================
// Fiat-Shamir transcript context (Section 3.4)
// ================================================================

public record FiatShamirContext(
    byte[] Sid, string IdProver, string IdVerifier,
    byte[] Commit1, byte[] Commit2);

// ================================================================
// Transcript — typed, length-prefixed binary hashing (SHA-512)
// ================================================================

public sealed class Transcript : IDisposable
{
    private readonly IncrementalHash _hash =
        IncrementalHash.CreateHash(HashAlgorithmName.SHA512);

    public Transcript Append(ReadOnlySpan<byte> data)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)data.Length);
        _hash.AppendData(len);
        _hash.AppendData(data);
        return this;
    }

    public Transcript Append(string s) =>
        Append(Encoding.UTF8.GetBytes(s).AsSpan());

    public Transcript Append(int value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buf, value);
        _hash.AppendData(buf);
        return this;
    }

    /// <summary>SHA-512 → 64 bytes → Ristretto255 scalar reduce → 32 bytes.</summary>
    public byte[] Finalize() =>
        Ristretto255.ScalarReduce64(_hash.GetHashAndReset());

    public void Dispose() => _hash.Dispose();
}

// ================================================================
// Crypto utilities
// ================================================================

public static class CryptoUtil
{
    public static byte[] GetRandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    public static (byte[] First, byte[] Second) CanonicalOrder(byte[] a, byte[] b)
    {
        int len = Math.Min(a.Length, b.Length);
        for (int i = 0; i < len; i++)
        {
            if (a[i] < b[i]) return (a, b);
            if (a[i] > b[i]) return (b, a);
        }
        return a.Length <= b.Length ? (a, b) : (b, a);
    }

    // ── Pedersen commitment: Com({P_i}; r) = r·H + Σ P_i ────────

    private static readonly byte[] PedersenH = Ristretto255.HashToPoint("pedersen_generator");

    public static byte[] Commit(byte[][] elements, byte[] nonce)
    {
        var result = Ristretto255.ScalarMul(PedersenH, nonce);
        for (int i = 0; i < elements.Length; i++)
            result = Ristretto255.PointAdd(result, elements[i]);
        return result;
    }

    public static bool VerifyCommit(byte[][] elements, byte[] nonce, byte[] expected) =>
        Ristretto255.PointEquals(Commit(elements, nonce), expected);

    // ── Fisher-Yates with rejection sampling ─────────────────────

    public static T[] SecureShuffle<T>(T[] arr)
    {
        var a = (T[])arr.Clone();
        Span<byte> buf = stackalloc byte[4];
        for (int i = a.Length - 1; i > 0; i--)
        {
            uint range = (uint)(i + 1);
            uint limit = uint.MaxValue - (uint.MaxValue % range);
            uint val;
            do
            {
                RandomNumberGenerator.Fill(buf);
                val = BitConverter.ToUInt32(buf);
            }
            while (val >= limit);

            int j = (int)(val % range);
            (a[i], a[j]) = (a[j], a[i]);
        }
        return a;
    }
}

// ================================================================
// Chaum-Pedersen proof (batched, over Ristretto255)
// ================================================================

public record CpProof(byte[] C, byte[] S);

public static class ChaumPedersen
{
    private static void AppendContext(
        Transcript t, FiatShamirContext ctx, byte[][] inputs, byte[][] outputs)
    {
        t.Append(ctx.Sid).Append(ctx.Commit1).Append(ctx.Commit2);
        for (int i = 0; i < inputs.Length; i++) t.Append(inputs[i]);
        for (int i = 0; i < outputs.Length; i++) t.Append(outputs[i]);
    }

    private static byte[][] ComputeWeights(
        byte[][] inputs, byte[][] outputs, FiatShamirContext ctx)
    {
        int n = inputs.Length;

        byte[] seed;
        using (var t = new Transcript())
        {
            t.Append("CP_batch_weight");
            AppendContext(t, ctx, inputs, outputs);
            seed = t.Finalize();
        }

        var weights = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            using var t = new Transcript();
            t.Append(seed).Append(i);
            var w = t.Finalize();
            if (CryptographicOperations.FixedTimeEquals(w, new byte[Ristretto255.ScalarBytes]))
                w[0] = 1;
            weights[i] = w;
        }
        return weights;
    }

    private static (byte[] A, byte[] B) WeightedSums(
        byte[][] inputs, byte[][] outputs, byte[][] weights)
    {
        int n = inputs.Length;
        var A = Ristretto255.ScalarMul(inputs[0], weights[0]);
        var B = Ristretto255.ScalarMul(outputs[0], weights[0]);
        for (int i = 1; i < n; i++)
        {
            A = Ristretto255.PointAdd(A, Ristretto255.ScalarMul(inputs[i], weights[i]));
            B = Ristretto255.PointAdd(B, Ristretto255.ScalarMul(outputs[i], weights[i]));
        }
        return (A, B);
    }

    private static byte[] ChallengeHash(
        FiatShamirContext ctx, byte[] A, byte[] B, byte[] R)
    {
        using var t = new Transcript();
        t.Append("CP_proof")
         .Append(ctx.Sid)
         .Append(ctx.IdProver).Append(ctx.IdVerifier)
         .Append(ctx.Commit1).Append(ctx.Commit2)
         .Append(A).Append(B).Append(R);
        return t.Finalize();
    }

    public static CpProof Prove(
        byte[][] inputs, byte[][] outputs, byte[] k, FiatShamirContext ctx)
    {
        var weights = ComputeWeights(inputs, outputs, ctx);
        var (A, B)  = WeightedSums(inputs, outputs, weights);
        var v       = Ristretto255.RandomScalar();
        var R       = Ristretto255.ScalarMul(A, v);
        var c       = ChallengeHash(ctx, A, B, R);
        var s       = Ristretto255.ScalarSub(v, Ristretto255.ScalarMulScalar(c, k));
        return new CpProof(c, s);
    }

    public static bool Verify(
        byte[][] inputs, byte[][] outputs, CpProof proof, FiatShamirContext ctx)
    {
        var weights = ComputeWeights(inputs, outputs, ctx);
        var (A, B)  = WeightedSums(inputs, outputs, weights);
        var R_prime = Ristretto255.PointAdd(
                          Ristretto255.ScalarMul(A, proof.S),
                          Ristretto255.ScalarMul(B, proof.C));
        var c_prime = ChallengeHash(ctx, A, B, R_prime);
        return Ristretto255.PointEquals(proof.C, c_prime);
    }
}
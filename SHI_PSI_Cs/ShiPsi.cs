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

    /// <summary>
    /// Hash-to-curve with explicit domain separation. Hashes
    /// SHA-512(len(dst) || dst || len(payload) || payload) and feeds the
    /// 64-byte digest to libsodium's Ristretto255 from_hash. Length-prefixing
    /// both fields makes the dst/payload split unambiguous, so distinct
    /// (dst, payload) pairs cannot collide.
    /// </summary>
    public static byte[] HashToPoint(string dst, ReadOnlySpan<byte> payload)
    {
        var dstBytes = Encoding.UTF8.GetBytes(dst);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        Span<byte> len = stackalloc byte[4];

        BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)dstBytes.Length);
        hasher.AppendData(len);
        hasher.AppendData(dstBytes);

        BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)payload.Length);
        hasher.AppendData(len);
        hasher.AppendData(payload);

        Span<byte> h = stackalloc byte[64];
        hasher.GetHashAndReset(h);

        var p = new byte[PointBytes];
        crypto_core_ristretto255_from_hash(p, h);
        return p;
    }

    public static byte[] HashToPoint(string dst, string payload) =>
        HashToPoint(dst, Encoding.UTF8.GetBytes(payload));

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

    public static string PointToHex(byte[] p) => Convert.ToHexString(p);

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

// ================================================================
// Byte-array key comparer (for HashSet/Dictionary keyed on points)
// ================================================================

public sealed class ByteArrayComparer : IEqualityComparer<byte[]>
{
    public static readonly ByteArrayComparer Instance = new();

    private ByteArrayComparer() { }

    public bool Equals(byte[]? x, byte[]? y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (x is null || y is null) return false;
        return x.AsSpan().SequenceEqual(y);
    }

    public int GetHashCode(byte[] obj)
    {
        // Ristretto255 encodings are 32 uniformly-distributed bytes, so any
        // 4 bytes are a good hash. Fall back to a length-mixed hash for short
        // inputs we don't expect in practice.
        if (obj.Length >= 4)
            return BinaryPrimitives.ReadInt32LittleEndian(obj);
        return HashCode.Combine(obj.Length);
    }
}

public static class CryptoUtil
{
    /// <summary>
    /// Switchover above which Parallel.For becomes worthwhile for the per-element
    /// EC operations in this protocol (each scalar mult is ~30 µs; thread-pool
    /// dispatch dominates well below this point).
    /// </summary>
    internal const int ParallelThreshold = 64;

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

    private static readonly byte[] PedersenH =
        Ristretto255.HashToPoint("shi_psi:pedersen_generator", ReadOnlySpan<byte>.Empty);

    public static byte[] Commit(byte[][] elements, byte[] nonce)
    {
        var rH = Ristretto255.ScalarMul(PedersenH, nonce);
        if (elements.Length == 0) return rH;

        byte[] sum;
        if (elements.Length < ParallelThreshold)
        {
            sum = elements[0];
            for (int i = 1; i < elements.Length; i++)
                sum = Ristretto255.PointAdd(sum, elements[i]);
        }
        else
        {
            var lockObj = new object();
            byte[]? psum = null;
            Parallel.For(0, elements.Length,
                () => (byte[]?)null,
                (i, _, local) => local is null ? elements[i] : Ristretto255.PointAdd(local, elements[i]),
                local => { lock (lockObj) { psum = psum is null ? local! : Ristretto255.PointAdd(psum, local!); } });
            sum = psum!;
        }

        return Ristretto255.PointAdd(rH, sum);
    }

    public static bool VerifyCommit(byte[][] elements, byte[] nonce, byte[] expected) =>
        Ristretto255.PointEquals(Commit(elements, nonce), expected);

    // ── Fisher-Yates with rejection sampling ─────────────────────

    public static void SecureShuffle<T>(Span<T> arr)
    {
        Span<byte> buf = stackalloc byte[4];
        for (int i = arr.Length - 1; i > 0; i--)
        {
            uint range = (uint)(i + 1);
            uint limit = uint.MaxValue - (uint.MaxValue % range);
            uint val;
            do
            {
                RandomNumberGenerator.Fill(buf);
                val = BinaryPrimitives.ReadUInt32LittleEndian(buf);
            }
            while (val >= limit);

            int j = (int)(val % range);
            (arr[i], arr[j]) = (arr[j], arr[i]);
        }
    }
}

// ================================================================
// Chaum-Pedersen proof (batched, over Ristretto255)
// ================================================================

public record CpProof(byte[] C, byte[] S);

public static class ChaumPedersen
{
    private static readonly byte[] ScalarZero = new byte[Ristretto255.ScalarBytes];
    private static void AppendContext(
        Transcript t, FiatShamirContext ctx, byte[][] inputs, byte[][] outputs)
    {
        t.Append(ctx.Sid).Append(ctx.Commit1).Append(ctx.Commit2);
        // Bind the array lengths so a (k, n-k) split cannot be re-interpreted
        // as a (k', n-k') split with the same concatenated body.
        t.Append(inputs.Length);
        for (int i = 0; i < inputs.Length; i++) t.Append(inputs[i]);
        t.Append(outputs.Length);
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
        if (n < CryptoUtil.ParallelThreshold)
        {
            for (int i = 0; i < n; i++)
                weights[i] = DeriveWeight(seed, i);
        }
        else
        {
            Parallel.For(0, n, i => weights[i] = DeriveWeight(seed, i));
        }
        return weights;
    }

    private static byte[] DeriveWeight(byte[] seed, int i)
    {
        using var t = new Transcript();
        t.Append(seed).Append(i);
        var w = t.Finalize();
        if (CryptographicOperations.FixedTimeEquals(w, ScalarZero))
            w[0] = 1;
        return w;
    }

    private static (byte[] A, byte[] B) WeightedSums(
        byte[][] inputs, byte[][] outputs, byte[][] weights)
    {
        int n = inputs.Length;
        var As = new byte[n][];
        var Bs = new byte[n][];

        if (n < CryptoUtil.ParallelThreshold)
        {
            for (int i = 0; i < n; i++)
            {
                As[i] = Ristretto255.ScalarMul(inputs[i], weights[i]);
                Bs[i] = Ristretto255.ScalarMul(outputs[i], weights[i]);
            }
            var sumA = As[0];
            var sumB = Bs[0];
            for (int i = 1; i < n; i++)
            {
                sumA = Ristretto255.PointAdd(sumA, As[i]);
                sumB = Ristretto255.PointAdd(sumB, Bs[i]);
            }
            return (sumA, sumB);
        }

        Parallel.For(0, n, i =>
        {
            As[i] = Ristretto255.ScalarMul(inputs[i], weights[i]);
            Bs[i] = Ristretto255.ScalarMul(outputs[i], weights[i]);
        });
        var lockObj = new object();
        byte[]? A = null, B = null;
        Parallel.For(0, n,
            () => ((byte[]?)null, (byte[]?)null),
            (i, _, local) => (
                local.Item1 is null ? As[i] : Ristretto255.PointAdd(local.Item1, As[i]),
                local.Item2 is null ? Bs[i] : Ristretto255.PointAdd(local.Item2, Bs[i])
            ),
            local =>
            {
                lock (lockObj)
                {
                    A = A is null ? local.Item1 : Ristretto255.PointAdd(A, local.Item1!);
                    B = B is null ? local.Item2 : Ristretto255.PointAdd(B, local.Item2!);
                }
            });
        return (A!, B!);
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
        var ck      = Ristretto255.ScalarMulScalar(c, k);
        var s       = Ristretto255.ScalarSub(v, ck);

        // Both v and c·k partially reveal the secret k if recovered together
        // with the public proof (s = v - c·k). Zero them as soon as s is built.
        CryptographicOperations.ZeroMemory(v);
        CryptographicOperations.ZeroMemory(ck);

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
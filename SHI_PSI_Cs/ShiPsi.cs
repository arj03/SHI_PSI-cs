// ShiPsi.cs — Size-Hiding Private Set Intersection Protocol
// WARNING: Prototype. Do not use for production without hardening.

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ShiPsiCs;

// ================================================================
// Ristretto255 via libsodium P/Invoke
// Points:  32-byte compressed Ristretto255 encodings.
// Scalars: 32-byte little-endian integers mod L.
// ================================================================

public static class Ristretto255
{
    public const int PointBytes  = 32;
    public const int ScalarBytes = 32;

    // ── EC operations ────────────────────────────────────────────

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_scalarmult_ristretto255(byte[] q, byte[] n, byte[] p);

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_core_ristretto255_from_hash(byte[] p, byte[] r);

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_core_ristretto255_add(byte[] r, byte[] p, byte[] q);

    // ── Scalar operations (all constant-time, mod L) ─────────────

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern void crypto_core_ristretto255_scalar_reduce(byte[] r, byte[] s);

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern void crypto_core_ristretto255_scalar_add(byte[] z, byte[] x, byte[] y);

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern void crypto_core_ristretto255_scalar_sub(byte[] z, byte[] x, byte[] y);

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern void crypto_core_ristretto255_scalar_mul(byte[] z, byte[] x, byte[] y);

    // ── Public EC methods ─────────────────────────────────────────

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

    // Hash arbitrary string to a Ristretto255 point via SHA-512 + from_hash.
    // from_hash applies the Elligator 2 map to each 32-byte half, then adds the results.
    public static byte[] HashToPoint(string element)
    {
        var h = SHA512.HashData(Encoding.UTF8.GetBytes("h2c|" + element));
        var p = new byte[PointBytes];
        crypto_core_ristretto255_from_hash(p, h);
        return p;
    }

    public static bool PointEquals(byte[] a, byte[] b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    public static string PointToHex(byte[] p) =>
        Convert.ToHexString(p).ToLowerInvariant();

    public static byte[] HexToPoint(string hex) =>
        Convert.FromHexString(hex);

    // ── Public scalar methods ─────────────────────────────────────

    // Reduce a 64-byte input to a 32-byte scalar mod L (constant-time).
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

    // Generate a uniform random non-zero scalar via 64 random bytes + reduce.
    public static byte[] RandomScalar()
    {
        byte[] r;
        do { r = ScalarReduce64(RandomNumberGenerator.GetBytes(64)); }
        while (CryptographicOperations.FixedTimeEquals(r, new byte[ScalarBytes]));
        return r;
    }
}

// ================================================================
// Crypto utilities
// ================================================================

public static class CryptoUtil
{
    public static byte[] GetRandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    private static byte[] Sha256(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s));

    private static string FormatPart(object p) =>
        p is byte[] b ? Ristretto255.PointToHex(b) : p.ToString()!;

    // Hash arbitrary parts to a SHA-256 digest (used for non-scalar contexts).
    public static byte[] HashConcat(params object[] parts) =>
        Sha256(string.Join("|", parts.Select(FormatPart)));

    // Hash arbitrary parts to a Ristretto255 scalar via SHA-512 + reduce (constant-time).
    public static byte[] HashToScalar(params object[] parts)
    {
        var h = SHA512.HashData(Encoding.UTF8.GetBytes(string.Join("|", parts.Select(FormatPart))));
        return Ristretto255.ScalarReduce64(h);
    }

    // Convenience alias
    public static byte[] HashToGroup(string element) => Ristretto255.HashToPoint(element);

    // ================================================================
    // Pedersen commitment: Com({P_i}; r) = r·H + Σ P_i
    // H is a second generator with unknown discrete log w.r.t. any other point.
    // ================================================================

    private static readonly byte[] PedersenH = Ristretto255.HashToPoint("pedersen_generator");

    public static byte[] Commit(byte[][] elements, byte[] nonce)
    {
        var result = Ristretto255.ScalarMul(PedersenH, nonce);
        foreach (var p in elements)
            result = Ristretto255.PointAdd(result, p);
        return result;
    }

    public static bool VerifyCommit(byte[][] elements, byte[] nonce, byte[] expected) =>
        Ristretto255.PointEquals(Commit(elements, nonce), expected);

    // Multiset equality via characteristic polynomial evaluation (Schwartz-Zippel).
    // Verifies {ordered} and {shuffled} are the same multiset: ∏(t - f(pᵢ)) = ∏(t - f(qⱼ))
    // Soundness error: N/L ≈ 2^-248. Not ZK — verifier computes both sides independently.
    public static bool VerifyShuffleMultiset(byte[][] ordered, byte[][] shuffled)
    {
        if (ordered.Length != shuffled.Length) return false;
        var t = HashToScalar(
            new object[] { "multiset_shuffle" }
                .Concat(ordered.Cast<object>())
                .Concat(shuffled.Cast<object>())
                .ToArray());
        var one = new byte[Ristretto255.ScalarBytes]; one[0] = 1;
        var ordProd  = (byte[])one.Clone();
        var shufProd = (byte[])one.Clone();
        foreach (var p in ordered)
            ordProd  = Ristretto255.ScalarMulScalar(ordProd,  Ristretto255.ScalarSub(t, HashToScalar(p)));
        foreach (var q in shuffled)
            shufProd = Ristretto255.ScalarMulScalar(shufProd, Ristretto255.ScalarSub(t, HashToScalar(q)));
        return Ristretto255.PointEquals(ordProd, shufProd);
    }

    public static T[] SecureShuffle<T>(T[] arr)
    {
        var a = (T[])arr.Clone();
        for (int i = a.Length - 1; i > 0; i--)
        {
            var j = (int)(BitConverter.ToUInt32(GetRandomBytes(4)) % (i + 1));
            (a[i], a[j]) = (a[j], a[i]);
        }
        return a;
    }
}

// ================================================================
// Chaum-Pedersen proof (batched, over Ristretto255)
// Proves: Q_i = k * P_i for all i, with the SAME k
// ================================================================

public record CpProof(byte[] C, byte[] S);

public static class ChaumPedersen
{
    private static byte[][] ComputeWeights(byte[][] inputs, byte[][] outputs)
    {
        // Hash all points once to a 32-byte seed, then derive each weight from seed||index.
        // O(N) hashing instead of O(N²).
        int n = inputs.Length;
        var seed = CryptoUtil.HashConcat(
            new object[] { "w_seed" }
                .Concat(inputs.Cast<object>())
                .Concat(outputs.Cast<object>())
                .ToArray());
        var weights = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            var w = CryptoUtil.HashToScalar(seed, i);
            // Ensure non-zero (probability 1/L ≈ 2^-252 of being zero)
            if (CryptographicOperations.FixedTimeEquals(w, new byte[Ristretto255.ScalarBytes]))
                w[0] = 1;
            weights[i] = w;
        }
        return weights;
    }

    private static (byte[] A, byte[] B) WeightedSums(byte[][] inputs, byte[][] outputs, byte[][] weights)
    {
        var A = Ristretto255.ScalarMul(inputs[0], weights[0]);
        var B = Ristretto255.ScalarMul(outputs[0], weights[0]);
        for (int i = 1; i < inputs.Length; i++)
        {
            A = Ristretto255.PointAdd(A, Ristretto255.ScalarMul(inputs[i], weights[i]));
            B = Ristretto255.PointAdd(B, Ristretto255.ScalarMul(outputs[i], weights[i]));
        }
        return (A, B);
    }

    public static CpProof Prove(byte[][] inputs, byte[][] outputs, byte[] k)
    {
        var weights  = ComputeWeights(inputs, outputs);
        var (A, B)   = WeightedSums(inputs, outputs, weights);
        var v        = Ristretto255.RandomScalar();
        var R        = Ristretto255.ScalarMul(A, v);
        var c        = CryptoUtil.HashToScalar("cp_c", A, B, R);
        var s        = Ristretto255.ScalarSub(v, Ristretto255.ScalarMulScalar(c, k));
        return new CpProof(c, s);
    }

    public static bool Verify(byte[][] inputs, byte[][] outputs, CpProof proof)
    {
        var weights  = ComputeWeights(inputs, outputs);
        var (A, B)   = WeightedSums(inputs, outputs, weights);
        var R_prime  = Ristretto255.PointAdd(
                           Ristretto255.ScalarMul(A, proof.S),
                           Ristretto255.ScalarMul(B, proof.C));
        var c_prime  = CryptoUtil.HashToScalar("cp_c", A, B, R_prime);
        return Ristretto255.PointEquals(proof.C, c_prime);
    }
}

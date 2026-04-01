// ShiPsi.cs — Size-Hiding Private Set Intersection Protocol
// WARNING: Prototype — not constant-time. Do not use for production without hardening.

using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ShiPsiCs;

// ================================================================
// Ristretto255 via libsodium P/Invoke
// Points are 32-byte compressed Ristretto255 encodings.
// Scalars are BigIntegers reduced mod L (the group order).
// ================================================================

public static class Ristretto255
{
    public const int PointBytes = 32;
    public const int ScalarBytes = 32;

    // Group order (prime subgroup, same as Ed25519)
    public static readonly BigInteger L =
        BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_scalarmult_ristretto255(byte[] q, byte[] n, byte[] p);

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_core_ristretto255_from_hash(byte[] p, byte[] r);

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_core_ristretto255_add(byte[] r, byte[] p, byte[] q);

    public static byte[] ScalarMul(byte[] point, BigInteger scalar)
    {
        var q = new byte[PointBytes];
        if (crypto_scalarmult_ristretto255(q, ScalarToBytes(scalar), point) != 0)
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

    // Encode scalar as 32-byte little-endian (libsodium convention).
    public static byte[] ScalarToBytes(BigInteger scalar)
    {
        var s = ((scalar % L) + L) % L;
        var result = new byte[ScalarBytes];
        var raw = s.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Copy(raw, result, Math.Min(raw.Length, ScalarBytes));
        return result;
    }
}

// ================================================================
// Crypto utilities
// ================================================================

public static class CryptoUtil
{
    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);
    public static byte[] Sha256(string data) => Sha256(Encoding.UTF8.GetBytes(data));

    public static BigInteger BytesToBigInt(byte[] bytes)
    {
        var reversed = new byte[bytes.Length + 1];
        for (int i = 0; i < bytes.Length; i++)
            reversed[bytes.Length - 1 - i] = bytes[i];
        return new BigInteger(reversed, isUnsigned: true);
    }

    public static string BigIntToHex(BigInteger n) =>
        n.ToString("x").PadLeft(64, '0');

    public static BigInteger HexToBigInt(string hex) =>
        BigInteger.Parse("0" + hex, System.Globalization.NumberStyles.AllowHexSpecifier);

    public static byte[] HashConcat(params object[] parts)
    {
        var strs = parts.Select(p =>
        {
            if (p is BigInteger bi) return BigIntToHex(bi);
            if (p is byte[] bytes) return Ristretto255.PointToHex(bytes);
            return p.ToString()!;
        });
        return Sha256(string.Join("|", strs));
    }

    public static BigInteger HashToBigInt(params object[] parts) =>
        BytesToBigInt(HashConcat(parts));

    // Convenience alias
    public static byte[] HashToGroup(string element) => Ristretto255.HashToPoint(element);

    // ================================================================
    // Pedersen commitment: Com({P_i}; r) = r·H + Σ P_i
    // H is a second generator with unknown discrete log w.r.t. any other point.
    // ================================================================

    private static readonly byte[] PedersenH = Ristretto255.HashToPoint("pedersen_generator");

    public static byte[] Commit(byte[][] elements, BigInteger nonce)
    {
        var result = Ristretto255.ScalarMul(PedersenH, nonce);
        foreach (var p in elements)
            result = Ristretto255.PointAdd(result, p);
        return result;
    }

    public static bool VerifyCommit(byte[][] elements, BigInteger nonce, byte[] expected)
    {
        var computed = Commit(elements, nonce);
        return Ristretto255.PointEquals(computed, expected);
    }

    // Multiset equality via characteristic polynomial evaluation (Schwartz-Zippel).
    // Verifies {ordered} and {shuffled} are the same multiset: ∏(t - f(pᵢ)) = ∏(t - f(qⱼ))
    // where t is a Fiat-Shamir challenge derived from both sets.
    // Soundness error: N/L ≈ 2^-248. Not ZK — verifier computes both sides independently.
    public static bool VerifyShuffleMultiset(byte[][] ordered, byte[][] shuffled)
    {
        if (ordered.Length != shuffled.Length) return false;
        var L = Ristretto255.L;
        var t = HashToBigInt(
            new object[] { "multiset_shuffle" }
                .Concat(ordered.Cast<object>())
                .Concat(shuffled.Cast<object>())
                .ToArray()) % L;
        BigInteger ordProd = 1, shufProd = 1;
        foreach (var p in ordered)
            ordProd = ordProd * ((t - HashToBigInt(p) % L + L) % L) % L;
        foreach (var q in shuffled)
            shufProd = shufProd * ((t - HashToBigInt(q) % L + L) % L) % L;
        return ordProd == shufProd;
    }

    public static byte[] GetRandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    public static BigInteger RandomScalar()
    {
        var bytes = GetRandomBytes(64);
        var n = BytesToBigInt(bytes);
        return (n % (Ristretto255.L - 2)) + 2; // uniform in [2, L-1]
    }

    public static T[] SecureShuffle<T>(T[] arr)
    {
        var a = (T[])arr.Clone();
        for (int i = a.Length - 1; i > 0; i--)
        {
            var bytes = GetRandomBytes(4);
            var val = BytesToBigInt(bytes);
            var j = (int)(val % (i + 1));
            (a[i], a[j]) = (a[j], a[i]);
        }
        return a;
    }
}

// ================================================================
// Chaum-Pedersen proof (batched, over Ristretto255)
// Proves: Q_i = k * P_i for all i, with the SAME k
// ================================================================

public record CpProof(BigInteger C, BigInteger S);

public static class ChaumPedersen
{
    private static BigInteger[] ComputeWeights(byte[][] inputs, byte[][] outputs)
    {
        var L = Ristretto255.L;
        int n = inputs.Length;
        var allPoints = inputs.Cast<object>().Concat(outputs.Cast<object>()).ToArray();
        var weights = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            var args = new object[] { "w", i }.Concat(allPoints).ToArray();
            weights[i] = (CryptoUtil.HashToBigInt(args) % (L - 1)) + 1;
        }
        return weights;
    }

    private static (byte[] A, byte[] B) WeightedSums(byte[][] inputs, byte[][] outputs, BigInteger[] weights)
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

    public static CpProof Prove(byte[][] inputs, byte[][] outputs, BigInteger k)
    {
        var L = Ristretto255.L;
        var weights = ComputeWeights(inputs, outputs);
        var (A, B) = WeightedSums(inputs, outputs, weights);
        var v = CryptoUtil.RandomScalar();
        var R = Ristretto255.ScalarMul(A, v);
        var c = ((CryptoUtil.HashToBigInt("cp_c", A, B, R) % L) + L) % L;
        var s = (((v - c * k) % L) + L) % L;
        return new CpProof(c, s);
    }

    public static bool Verify(byte[][] inputs, byte[][] outputs, CpProof proof)
    {
        var L = Ristretto255.L;
        var weights = ComputeWeights(inputs, outputs);
        var (A, B) = WeightedSums(inputs, outputs, weights);
        var sA = Ristretto255.ScalarMul(A, proof.S);
        var cB = Ristretto255.ScalarMul(B, proof.C);
        var R_prime = Ristretto255.PointAdd(sA, cB);
        var c_prime = ((CryptoUtil.HashToBigInt("cp_c", A, B, R_prime) % L) + L) % L;
        return proof.C == c_prime;
    }
}

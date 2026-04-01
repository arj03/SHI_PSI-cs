// ShiPsi.cs — Size-Hiding Private Set Intersection Protocol
// WARNING: Prototype — not constant-time. Do not use for production without hardening.

using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace ShiPsiCs;

// ================================================================
// Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2  over GF(p)
// p = 2^255 - 19, order L (of base point)
// ================================================================

// Extended projective point: represents affine (X/Z, Y/Z) with T = X*Y/Z
public readonly struct ExtPoint(BigInteger x, BigInteger y, BigInteger z, BigInteger t)
{
    public readonly BigInteger X = x, Y = y, Z = z, T = t;
}

public static class Ed25519
{
    public static readonly BigInteger FieldP = BigInteger.Pow(2, 255) - 19;

    // d = -121665/121666 mod p
    public static readonly BigInteger D =
        BigInteger.Parse("37095705934669439343138083508754565189542113879843219016388785533085940283555");

    // Group order (of the base point, prime subgroup)
    public static readonly BigInteger L =
        BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");

    // Identity point in extended coordinates
    public static readonly ExtPoint Identity = new(0, 1, 1, 0);

    public static BigInteger FMod(BigInteger a)
    {
        var r = a % FieldP;
        return r < 0 ? r + FieldP : r;
    }

    private static BigInteger FInv(BigInteger a) => BigInteger.ModPow(a, FieldP - 2, FieldP);

    // Create extended point from affine (x, y)
    public static ExtPoint FromAffine(BigInteger x, BigInteger y)
    {
        return new ExtPoint(FMod(x), FMod(y), 1, FMod(x * y % FieldP));
    }

    // Convert to affine (x, y) — single inversion
    public static (BigInteger X, BigInteger Y) ToAffine(ExtPoint p)
    {
        var zInv = FInv(p.Z);
        return (FMod(p.X * zInv % FieldP), FMod(p.Y * zInv % FieldP));
    }

    // Extended twisted Edwards addition (a = -1)
    // From Hisil-Wong-Carter-Dawson 2008: add-2008-hwcd
    public static ExtPoint PointAdd(ExtPoint p1, ExtPoint p2)
    {
        var A = p1.X * p2.X % FieldP;
        var B = p1.Y * p2.Y % FieldP;
        var C = p1.T * D % FieldP * p2.T % FieldP;
        var DD = p1.Z * p2.Z % FieldP;
        var E = ((p1.X + p1.Y) * (p2.X + p2.Y) - A - B) % FieldP;
        var F = (DD - C) % FieldP;
        var G = (DD + C) % FieldP;
        var H = (B + A) % FieldP; // a=-1: B - a*A = B + A
        return new ExtPoint(
            FMod(E * F % FieldP),
            FMod(G * H % FieldP),
            FMod(F * G % FieldP),
            FMod(E * H % FieldP));
    }

    // Extended twisted Edwards doubling (a = -1)
    public static ExtPoint PointDouble(ExtPoint p)
    {
        var a = p.X * p.X % FieldP;
        var b = p.Y * p.Y % FieldP;
        var c = p.Z * p.Z * 2 % FieldP;
        var d = FMod(-a); // a=-1: a*A = -A
        var e = ((p.X + p.Y) * (p.X + p.Y) - a - b) % FieldP;
        var g = (d + b) % FieldP;
        var f = (g - c) % FieldP;
        var h = (d - b) % FieldP;
        return new ExtPoint(
            FMod(e * f % FieldP),
            FMod(g * h % FieldP),
            FMod(f * g % FieldP),
            FMod(e * h % FieldP));
    }

    // Scalar multiplication via double-and-add (no inversions until ToAffine)
    public static ExtPoint ScalarMulExt(ExtPoint point, BigInteger scalar)
    {
        scalar = ((scalar % L) + L) % L;
        var result = Identity;
        var current = point;
        while (scalar > 0)
        {
            if (!scalar.IsEven)
                result = PointAdd(result, current);
            current = PointDouble(current);
            scalar >>= 1;
        }
        return result;
    }

    // Convenience: affine in, affine out
    public static (BigInteger X, BigInteger Y) ScalarMul(
        (BigInteger X, BigInteger Y) point, BigInteger scalar)
    {
        var ext = FromAffine(point.X, point.Y);
        return ToAffine(ScalarMulExt(ext, scalar));
    }

    // Encode a point to a canonical hex string for comparison/hashing
    public static string PointToHex((BigInteger X, BigInteger Y) point)
    {
        var xHex = point.X.ToString("x").PadLeft(64, '0');
        var yHex = point.Y.ToString("x").PadLeft(64, '0');
        return xHex + yHex;
    }

    public static bool PointEquals((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) b)
    {
        return FMod(a.X) == FMod(b.X) && FMod(a.Y) == FMod(b.Y);
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

    public static string BigIntToHex(BigInteger n)
    {
        var hex = n.ToString("x");
        return hex.PadLeft(64, '0');
    }

    public static BigInteger HexToBigInt(string hex)
    {
        return BigInteger.Parse("0" + hex, System.Globalization.NumberStyles.AllowHexSpecifier);
    }

    public static byte[] HashConcat(params object[] parts)
    {
        var strs = parts.Select(p =>
        {
            if (p is BigInteger bi) return BigIntToHex(bi);
            if (p is ValueTuple<BigInteger, BigInteger> pt) return Ed25519.PointToHex(pt);
            return p.ToString()!;
        });
        return Sha256(string.Join("|", strs));
    }

    public static BigInteger HashToBigInt(params object[] parts) => BytesToBigInt(HashConcat(parts));

    // ================================================================
    // Elligator 2 hash-to-curve (RFC 9380, Section 6.7.1)
    // Maps arbitrary strings to Ed25519 prime-order subgroup points.
    // Deterministic, constant number of operations (no retry loop).
    // ================================================================

    // Montgomery curve Curve25519: v^2 = u^3 + A*u^2 + u
    private static readonly BigInteger MontA = 486662;
    private static readonly BigInteger ElligZ = 2; // non-square in GF(p)
    private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (Ed25519.FieldP - 1) / 4, Ed25519.FieldP);
    private static readonly BigInteger SqrtNeg486664 = ComputeSqrt((-486664 % Ed25519.FieldP + Ed25519.FieldP) % Ed25519.FieldP);

    private static BigInteger FMod(BigInteger a)
    {
        var r = a % Ed25519.FieldP;
        return r < 0 ? r + Ed25519.FieldP : r;
    }

    private static BigInteger FInv(BigInteger a) => BigInteger.ModPow(a, Ed25519.FieldP - 2, Ed25519.FieldP);

    // Compute sqrt for p ≡ 5 mod 8 (Atkin's algorithm)
    private static BigInteger ComputeSqrt(BigInteger a)
    {
        var p = Ed25519.FieldP;
        var candidate = BigInteger.ModPow(a, (p + 3) / 8, p);
        if (candidate * candidate % p == a % p) return candidate;
        candidate = candidate * SqrtM1 % p;
        if (FMod(candidate * candidate % p) == FMod(a)) return FMod(candidate);
        throw new InvalidOperationException("Not a quadratic residue");
    }

    private static bool IsSquare(BigInteger a)
    {
        var p = Ed25519.FieldP;
        if (a == 0) return true;
        return BigInteger.ModPow(FMod(a), (p - 1) / 2, p) == 1;
    }

    // Least significant bit (sgn0 per RFC 9380)
    private static int Sgn0(BigInteger a) => (int)(FMod(a) % 2);

    // Elligator 2 map: field element → Montgomery point (u, v)
    private static (BigInteger u, BigInteger v) Elligator2Map(BigInteger r)
    {
        var p = Ed25519.FieldP;
        var A = MontA;

        var r2 = r * r % p;
        var tv1 = ElligZ * r2 % p;
        if (tv1 == p - 1) tv1 = 0; // exceptional: Z*r^2 == -1

        // x1 = -A / (1 + Z*r^2)
        var x1 = FMod((-A % p + p) * FInv(FMod(1 + tv1)) % p);

        // gx1 = x1^3 + A*x1^2 + x1
        var x1sq = x1 * x1 % p;
        var gx1 = FMod((x1sq * x1 + A * x1sq + x1) % p);

        // x2 = -x1 - A
        var x2 = FMod(-x1 - A);
        var x2sq = x2 * x2 % p;
        var gx2 = FMod((x2sq * x2 + A * x2sq + x2) % p);

        BigInteger x, y2;
        if (IsSquare(gx1)) { x = x1; y2 = gx1; }
        else { x = x2; y2 = gx2; }

        var y = ComputeSqrt(y2);

        // Match signs: sgn0(y) == sgn0(r)
        if (Sgn0(r) != Sgn0(y))
            y = FMod(p - y);

        return (x, y);
    }

    // Montgomery (u, v) → Edwards (x_e, y_e)
    private static (BigInteger X, BigInteger Y) MontgomeryToEdwards(BigInteger u, BigInteger v)
    {
        var p = Ed25519.FieldP;
        if (v == 0) // map to 2-torsion point (0, -1) or identity (0, 1)
            return u == 0 ? (BigInteger.Zero, BigInteger.One) : (BigInteger.Zero, FMod(p - 1));

        var xe = FMod(SqrtNeg486664 * u % p * FInv(v) % p);
        var ye = FMod((u - 1 + p) % p * FInv(FMod(u + 1)) % p);
        return (xe, ye);
    }

    public static (BigInteger X, BigInteger Y) HashToGroup(string element)
    {
        var p = Ed25519.FieldP;

        // Hash to two independent field elements
        var u0 = BytesToBigInt(Sha256($"h2c|0|{element}")) % p;
        var u1 = BytesToBigInt(Sha256($"h2c|1|{element}")) % p;

        // Map each to Montgomery curve via Elligator 2
        var (mu0, mv0) = Elligator2Map(u0);
        var (mu1, mv1) = Elligator2Map(u1);

        // Convert to Edwards
        var (X, Y) = MontgomeryToEdwards(mu0, mv0);
        var p1 = MontgomeryToEdwards(mu1, mv1);

        // Add points and clear cofactor (×8)
        var sum = Ed25519.PointAdd(Ed25519.FromAffine(X, Y), Ed25519.FromAffine(p1.X, p1.Y));
        var result = Ed25519.ToAffine(Ed25519.ScalarMulExt(sum, 8));

        return result;
    }

    public static byte[] GetRandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    public static BigInteger RandomScalar()
    {
        var bytes = GetRandomBytes(64);
        var n = BytesToBigInt(bytes);
        return (n % (Ed25519.L - 2)) + 2; // uniform in [2, L-1]
    }

    // Pedersen commitment: Com({P_i}; r) = r·H + Σ P_i
    // H is a second generator whose discrete log w.r.t. any other point is unknown.
    private static readonly (BigInteger X, BigInteger Y) PedersenH = HashToGroup("pedersen_generator");

    public static (BigInteger X, BigInteger Y) Commit((BigInteger X, BigInteger Y)[] elements, BigInteger nonce)
    {
        // r·H
        var result = Ed25519.ScalarMulExt(Ed25519.FromAffine(PedersenH.X, PedersenH.Y), nonce);
        // + Σ P_i
        foreach (var p in elements)
            result = Ed25519.PointAdd(result, Ed25519.FromAffine(p.X, p.Y));
        return Ed25519.ToAffine(result);
    }

    public static bool VerifyCommit((BigInteger X, BigInteger Y)[] elements, BigInteger nonce,
        (BigInteger X, BigInteger Y) expected)
    {
        var computed = Commit(elements, nonce);
        return Ed25519.PointEquals(computed, expected);
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
// Chaum-Pedersen proof (batched, over Ed25519)
// Proves: Q_i = k * P_i for all i, with the SAME k
// ================================================================

public record CpProof(BigInteger C, BigInteger S);

public static class ChaumPedersen
{
    private static BigInteger[] ComputeWeights(
        (BigInteger X, BigInteger Y)[] inputs,
        (BigInteger X, BigInteger Y)[] outputs)
    {
        var L = Ed25519.L;
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

    // Compute weighted sums in projective coordinates, return affine
    private static ((BigInteger X, BigInteger Y) A, (BigInteger X, BigInteger Y) B) WeightedSums(
        (BigInteger X, BigInteger Y)[] inputs,
        (BigInteger X, BigInteger Y)[] outputs,
        BigInteger[] weights)
    {
        int n = inputs.Length;
        var aExt = Ed25519.Identity;
        var bExt = Ed25519.Identity;
        for (int i = 0; i < n; i++)
        {
            aExt = Ed25519.PointAdd(aExt, Ed25519.ScalarMulExt(Ed25519.FromAffine(inputs[i].X, inputs[i].Y), weights[i]));
            bExt = Ed25519.PointAdd(bExt, Ed25519.ScalarMulExt(Ed25519.FromAffine(outputs[i].X, outputs[i].Y), weights[i]));
        }
        return (Ed25519.ToAffine(aExt), Ed25519.ToAffine(bExt));
    }

    public static CpProof Prove(
        (BigInteger X, BigInteger Y)[] inputs,
        (BigInteger X, BigInteger Y)[] outputs,
        BigInteger k)
    {
        var L = Ed25519.L;
        var weights = ComputeWeights(inputs, outputs);
        var (A, B) = WeightedSums(inputs, outputs, weights);

        var v = CryptoUtil.RandomScalar();
        var R = Ed25519.ScalarMul(A, v);
        var c = ((CryptoUtil.HashToBigInt("cp_c", A, B, R) % L) + L) % L;
        var s = (((v - c * k) % L) + L) % L;
        return new CpProof(c, s);
    }

    public static bool Verify(
        (BigInteger X, BigInteger Y)[] inputs,
        (BigInteger X, BigInteger Y)[] outputs,
        CpProof proof)
    {
        var L = Ed25519.L;
        var weights = ComputeWeights(inputs, outputs);
        var (A, B) = WeightedSums(inputs, outputs, weights);

        // R' = s*A + c*B  (stay in projective for the add)
        var sA = Ed25519.ScalarMulExt(Ed25519.FromAffine(A.X, A.Y), proof.S);
        var cB = Ed25519.ScalarMulExt(Ed25519.FromAffine(B.X, B.Y), proof.C);
        var R_prime = Ed25519.ToAffine(Ed25519.PointAdd(sA, cB));
        var c_prime = ((CryptoUtil.HashToBigInt("cp_c", A, B, R_prime) % L) + L) % L;
        return proof.C == c_prime;
    }
}
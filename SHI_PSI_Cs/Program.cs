// Test program for SHI-PSI

using System.Diagnostics;
using ShiPsiCs;

Sodium.SodiumCore.Init();

// Test 3: Full protocol — simple case
Console.WriteLine("\n=== Test 3: Protocol (basic) ===");
var sw = Stopwatch.StartNew();
string[] aliceItems = ["apple", "banana", "cherry"];
string[] bobItems = ["banana", "date", "cherry", "elderberry"];
var (aliceResult, bobResult) = PsiSession.RunProtocol(aliceItems, bobItems, 10);
sw.Stop();
Array.Sort(aliceResult);
Array.Sort(bobResult);
string[] expectedIntersection = ["banana", "cherry"];
Console.WriteLine($"Alice's items: [{string.Join(", ", aliceItems)}]");
Console.WriteLine($"Bob's items: [{string.Join(", ", bobItems)}]");
Console.WriteLine($"Alice's intersection: [{string.Join(", ", aliceResult)}]");
Console.WriteLine($"Bob's intersection:   [{string.Join(", ", bobResult)}]");
Console.WriteLine($"Expected:             [{string.Join(", ", expectedIntersection)}]");
Console.WriteLine($"Alice correct: {aliceResult.SequenceEqual(expectedIntersection)}");
Console.WriteLine($"Bob correct:   {bobResult.SequenceEqual(expectedIntersection)}");
Console.WriteLine($"Time: {sw.ElapsedMilliseconds} ms");

// Test 4: No intersection
Console.WriteLine("\n=== Test 4: Protocol (no overlap) ===");
var (a5, b5) = PsiSession.RunProtocol(["a", "b", "c"], ["d", "e", "f"], 10);
Console.WriteLine($"Alice: [{string.Join(", ", a5)}] (should be [])");
Console.WriteLine($"Bob:   [{string.Join(", ", b5)}] (should be [])");
Console.WriteLine($"Correct: {a5.Length == 0 && b5.Length == 0}");

// Test 5: Full overlap
Console.WriteLine("\n=== Test 5: Protocol (full overlap) ===");
var (a6, b6) = PsiSession.RunProtocol(["x", "y", "z"], ["x", "y", "z"], 10);
Array.Sort(a6);
Array.Sort(b6);
Console.WriteLine($"Alice: [{string.Join(", ", a6)}]");
Console.WriteLine($"Bob:   [{string.Join(", ", b6)}]");
Console.WriteLine($"Correct: {a6.SequenceEqual(new[] { "x", "y", "z" })}");

// Test 6: Different set sizes (size-hiding)
Console.WriteLine("\n=== Test 6: Protocol (different sizes, N=10) ===");
var (a7, b7) = PsiSession.RunProtocol(
    ["only_one"],
    ["only_one", "b", "c", "d", "e", "f", "g", "h"],
    10);
Console.WriteLine($"Alice: [{string.Join(", ", a7)}]");
Console.WriteLine($"Bob:   [{string.Join(", ", b7)}]");
Console.WriteLine($"Correct: {a7.SequenceEqual(new[] { "only_one" }) && b7.SequenceEqual(new[] { "only_one" })}");

Console.WriteLine("\n=== All tests complete ===");

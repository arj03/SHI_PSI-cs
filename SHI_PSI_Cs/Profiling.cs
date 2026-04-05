// Profiling.cs — phase-by-phase timing for LargerN (N=500)

using System.Diagnostics;
using Xunit;

namespace ShiPsiCs.Tests;

public class Profiling
{
    static void Log(string s) => Console.Error.WriteLine(s);

    static long Time(string label, Action action)
    {
        var sw = Stopwatch.StartNew();
        action();
        sw.Stop();
        Log($"  {label,-42} {sw.ElapsedMilliseconds,6} ms");
        return sw.ElapsedMilliseconds;
    }

    static void Profile(string label, string[] setA, string[] setB, int n)
    {
        // Cold — first call includes JIT compilation; this is what xUnit measures per test
        var coldSw = Stopwatch.StartNew();
        PsiSession.RunProtocol(setA, setB, n);
        var cold = coldSw.ElapsedMilliseconds;

        // Warm — steady-state throughput after JIT
        var times = new long[7];
        for (int i = 0; i < times.Length; i++)
        {
            var sw = Stopwatch.StartNew();
            PsiSession.RunProtocol(setA, setB, n);
            times[i] = sw.ElapsedMilliseconds;
        }
        Array.Sort(times);
        Log($"  {label,-36}  cold={cold,5}ms  warm p50={times[3],4}ms  warm p95={times[6],4}ms");
    }

    [Fact]
    public void ProfileTests()
    {
        Log($"\n  {"Test",-36}  {"cold (=xUnit)",13}  {"warm p50",10}  {"warm p95",10}");
        Log("  " + new string('-', 76));
        Profile("BasicIntersection (N=10)",
            ["apple", "banana", "cherry"],
            ["banana", "date", "cherry", "elderberry"], 10);
        Profile("LargerN (N=500)",
            ["a", "b"], ["b", "c"], 500);
        Log("");
    }
}

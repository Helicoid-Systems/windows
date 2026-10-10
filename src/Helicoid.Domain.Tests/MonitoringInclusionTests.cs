using Helicoid.Domain.Model;
using Helicoid.Domain.Overview;
using Xunit;

namespace Helicoid.Domain.Tests;

public class MonitoringInclusionTests
{
    private static readonly ComputerId A = ComputerId.Parse("pc-a");
    private static readonly ComputerId B = ComputerId.Parse("pc-b");
    private static readonly ComputerId C = ComputerId.Parse("pc-c");

    [Fact]
    public void AllMode_ResolvesToCurrentAuthorizedInventory()
    {
        var inclusion = MonitoringInclusion.All();
        var resolved = inclusion.Resolve(new[] { A, B, C });
        Assert.Equal(new[] { A, B, C }, resolved);
    }

    [Fact]
    public void ExplicitMode_NeverExpandsToNewInventory()
    {
        var inclusion = MonitoringInclusion.Explicit(new[] { A });
        var resolved = inclusion.Resolve(new[] { A, B, C });
        Assert.Equal(new[] { A }, resolved);
    }

    [Fact]
    public void AllMode_IncludesNewlyEligibleInventory_UnderD18()
    {
        var inclusion = MonitoringInclusion.All();
        var before = inclusion.Resolve(new[] { A });
        var after = inclusion.Resolve(new[] { A, B });
        Assert.Equal(new[] { A }, before);
        Assert.Equal(new[] { A, B }, after);
    }

    [Fact]
    public void Restore_AllMode_StaysAll()
    {
        var inclusion = MonitoringInclusion.Restore(true, new[] { A }, new[] { B });
        Assert.True(inclusion.IsAllMode);
        Assert.Equal(new[] { B }, inclusion.Resolve(new[] { B }));
    }

    [Fact]
    public void Restore_Explicit_DropsNoLongerAuthorizedIds()
    {
        var inclusion = MonitoringInclusion.Restore(false, new[] { A, C }, new[] { A, B });
        Assert.False(inclusion.IsAllMode);
        Assert.Equal(new[] { A }, inclusion.Resolve(new[] { A, B }));
    }

    [Fact]
    public void UncheckAll_YieldsEmptyExplicitSet()
    {
        var inclusion = MonitoringInclusion.All();
        inclusion.ClearToEmptyExplicit();
        Assert.False(inclusion.IsAllMode);
        Assert.Empty(inclusion.Resolve(new[] { A, B }));
    }

    [Fact]
    public void CheckingAll_SelectsAllMode()
    {
        var inclusion = MonitoringInclusion.Explicit(new[] { A });
        inclusion.CheckAll();
        Assert.True(inclusion.IsAllMode);
        Assert.Equal(new[] { A, B }, inclusion.Resolve(new[] { A, B }));
    }
}

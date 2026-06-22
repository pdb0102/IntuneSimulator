using IntuneSimulator.Core.Failure;
using Xunit;

namespace IntuneSimulator.Tests;

public class FailureEngineTests
{
    [Fact]
    public void Matrix_has_expected_size_and_order()
    {
        Assert.Equal(32, FailureChain.Matrix.Count);
        Assert.Equal("instance-discovery", FailureChain.Matrix[0].EndpointId);
        Assert.Equal(FailureMode.Timeout, FailureChain.Matrix[0].Mode);
        Assert.Equal("scep-action", FailureChain.Matrix[^1].EndpointId);
        Assert.Equal(FailureMode.ScepError, FailureChain.Matrix[^1].Mode);
    }

    [Fact]
    public void Manual_injects_only_at_cursor_endpoint()
    {
        var e = new FailureFlowEngine { Mode = FailureFlowMode.Manual };
        e.SetStep(0); // instance-discovery / Timeout
        Assert.Equal(FailureMode.Timeout, e.ResolveInjection("instance-discovery"));
        Assert.Null(e.ResolveInjection("scep-action"));
    }

    [Fact]
    public void Advance_walks_to_success()
    {
        var e = new FailureFlowEngine { Mode = FailureFlowMode.Manual };
        for (int i = 0; i < FailureChain.Matrix.Count; i++) e.Advance();
        Assert.Null(e.Current());                       // exhausted
        Assert.Null(e.ResolveInjection("scep-action")); // everything succeeds
    }

    [Fact]
    public void Reset_returns_to_start()
    {
        var e = new FailureFlowEngine { Mode = FailureFlowMode.Manual };
        e.SetStep(10);
        e.Reset();
        Assert.Equal(0, e.StepIndex);
    }

    [Fact]
    public void Auto_advances_on_new_flow_after_serving()
    {
        var e = new FailureFlowEngine { Mode = FailureFlowMode.Auto };
        // Cursor at step 0 = instance-discovery/Timeout. First flow serves it.
        Assert.Equal(FailureMode.Timeout, e.ResolveInjection("instance-discovery"));
        Assert.Equal(0, e.StepIndex);
        // Next flow: first-endpoint hit advances to step 1 (instance-discovery/ConnectionRefused).
        Assert.Equal(FailureMode.ConnectionRefused, e.ResolveInjection("instance-discovery"));
        Assert.Equal(1, e.StepIndex);
    }

    [Fact]
    public void Doc_has_a_row_per_step()
    {
        var md = FailureFlowDoc.Render();
        foreach (var s in FailureChain.Matrix)
            Assert.Contains($"| {s.Index + 1} |", md);
    }
}

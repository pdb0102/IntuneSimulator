using IntuneSimulator.Core.Failure;
using Xunit;

namespace IntuneSimulator.Tests;

public class FailureDocTests
{
    [Fact]
    public void Doc_row_count_matches_matrix()
    {
        var md = FailureFlowDoc.Render();
        int rows = md.Split('\n').Count(l => l.StartsWith("| ") && !l.StartsWith("| Step") && !l.StartsWith("|---"));
        Assert.Equal(FailureChain.Matrix.Count + 1, rows); // +1 for the final success row
    }
}

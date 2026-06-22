using System.Threading.Tasks;
using ScepWright.Crypto;

namespace ScepWright.Core.Challenge;

/// <summary>A challenge source that returns a fixed, caller-supplied value.</summary>
public sealed class ExplicitChallengeSource : IChallengeSource {
    private readonly string _value;

    /// <summary>Creates a source that always returns the given challenge value.</summary>
    public ExplicitChallengeSource(string value) { _value = value; }

    /// <inheritdoc/>
    public bool TryGet(out string challenge, out string error) {
        challenge = _value;
        error = string.Empty;
        return true;
    }

    /// <inheritdoc/>
    public Task<ScepResult<string>> GetAsync() => Task.FromResult(ScepResult<string>.Ok(_value));
}

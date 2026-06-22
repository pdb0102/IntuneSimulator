using System.Threading.Tasks;
using ScepWright.Crypto;

namespace ScepWright.Core.Challenge;

/// <summary>A source of SCEP challenge passwords (explicit value, NDES admin page, or simulator).</summary>
public interface IChallengeSource {
    /// <summary>Synchronously obtains a challenge password; returns false with an error on failure.</summary>
    bool TryGet(out string challenge, out string error);
    /// <summary>Asynchronously obtains a challenge password.</summary>
    Task<ScepResult<string>> GetAsync();
}

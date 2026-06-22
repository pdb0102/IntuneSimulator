using System.IO;
using System.Text.Json;

namespace ScepWright.Core.Storage;

/// <summary>Persisted client-wide defaults, stored as config.json under the data root.</summary>
public sealed class ClientConfig {
    /// <summary>Gets or sets the path to a custom crypto provider DLL; null uses the built-in provider.</summary>
    public string? CryptoProviderPath { get; set; }
    /// <summary>Gets or sets the default key spec. Defaults to rsa:2048.</summary>
    public string KeySpec { get; set; } = "rsa:2048";
    /// <summary>Gets or sets the transport timeout in seconds. Defaults to 30.</summary>
    public int TimeoutSeconds { get; set; } = 30;
    /// <summary>Gets or sets the minimum acceptable RSA key size used by the opinion engine. Defaults to 2048.</summary>
    public int MinRsaKeyBits { get; set; } = 2048;

    /// <summary>Loads config.json from the data root, returning defaults if it is missing or unreadable.</summary>
    public static ClientConfig Load(string root) {
        string config_path;

        config_path = Path.Combine(root, "config.json");
        if (!File.Exists(config_path)) {
            return new ClientConfig();
        }

        try {
            ClientConfig? loaded;

            loaded = JsonSerializer.Deserialize<ClientConfig>(File.ReadAllText(config_path));
            return loaded ?? new ClientConfig();
        } catch {
            return new ClientConfig();
        }
    }

    /// <summary>Writes the config to config.json under the data root, creating the directory if needed.</summary>
    public void Save(string root) {
        string config_path;

        config_path = Path.Combine(root, "config.json");
        Directory.CreateDirectory(root);
        File.WriteAllText(config_path, JsonSerializer.Serialize(this));
    }
}

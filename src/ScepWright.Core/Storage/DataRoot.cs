using System;
using System.IO;
using System.Text.Json;

namespace ScepWright.Core.Storage;

/// <summary>Resolves the SCEPwright data-root directory from explicit path, environment, or breadcrumb.</summary>
public static class DataRoot {
    private const string BreadcrumbFileName = ".scepwright.json";
    private const string DefaultDirName = ".scepwright";
    private const string HomeEnvVarName = "SCEPWRIGHT_HOME";

    /// <summary>
    /// Resolves the data root. Precedence: an explicit directory, then <c>SCEPWRIGHT_HOME</c> (a
    /// transient override that writes no breadcrumb), then a breadcrumb in the user's home, then the
    /// default <c>~/.scepwright</c> (which is recorded in a breadcrumb best-effort).
    /// </summary>
    public static string Resolve(string? explicit_dir, string? home_override = null) {
        return Resolve(explicit_dir, home_override, Environment.GetEnvironmentVariable(HomeEnvVarName));
    }

    internal static string Resolve(string? explicit_dir, string? home_override, string? env_home) {
        string home;
        string breadcrumb_path;
        string default_root;

        if (!string.IsNullOrEmpty(explicit_dir)) {
            return explicit_dir;
        }

        if (!string.IsNullOrEmpty(env_home)) {
            return env_home;   // transient override — do NOT write a breadcrumb
        }

        home = home_override ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        breadcrumb_path = Path.Combine(home, BreadcrumbFileName);
        default_root = Path.Combine(home, DefaultDirName);

        if (File.Exists(breadcrumb_path)) {
            try {
                string json;
                BreadcrumbData? data;

                json = File.ReadAllText(breadcrumb_path);
                data = JsonSerializer.Deserialize<BreadcrumbData>(json);
                if (data != null && !string.IsNullOrEmpty(data.Root)) {
                    return data.Root;
                }
            } catch {
                // fall through to default
            }
        }

        try {
            BreadcrumbData breadcrumb;
            string json;

            breadcrumb = new BreadcrumbData { Root = default_root };
            json = JsonSerializer.Serialize(breadcrumb);
            File.WriteAllText(breadcrumb_path, json);
        } catch {
            // best-effort; never throw if home unwritable
        }

        return default_root;
    }

    private sealed class BreadcrumbData {
        public string Root { get; set; } = string.Empty;
    }
}

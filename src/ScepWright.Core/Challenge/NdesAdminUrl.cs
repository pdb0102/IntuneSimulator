namespace ScepWright.Core.Challenge;

/// <summary>Derives the NDES mscep_admin URL from a SCEP endpoint URL.</summary>
public static class NdesAdminUrl {
    /// <summary>
    /// Returns <paramref name="explicit_admin_url"/> if given; otherwise derives the admin page parallel
    /// to the SCEP endpoint (Microsoft <c>mscep</c> → <c>mscep_admin</c>, or a generic sibling rule).
    /// </summary>
    public static string Derive(string scep_url, string? explicit_admin_url = null) {
        System.Uri uri;
        string path;

        if (!string.IsNullOrEmpty(explicit_admin_url)) { return explicit_admin_url!; }

        uri = new System.Uri(scep_url);
        path = uri.AbsolutePath;

        if (path.Contains("/mscep/", System.StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/mscep", System.StringComparison.OrdinalIgnoreCase)) {
            // Microsoft NDES layout: the admin page is a sibling of the 'mscep' service directory
            // (…/certsrv/mscep[/pkiclient.exe] -> …/certsrv/mscep_admin/).
            path = path.Replace("/mscep/", "/mscep_admin/", System.StringComparison.OrdinalIgnoreCase);
            if (path.EndsWith("/mscep", System.StringComparison.OrdinalIgnoreCase)) {
                path = path.Substring(0, path.Length - "/mscep".Length) + "/mscep_admin/";
            }
            if (path.EndsWith("pkiclient.exe", System.StringComparison.OrdinalIgnoreCase)) {
                path = path.Substring(0, path.Length - "pkiclient.exe".Length);
            }
        } else {
            // Generic rule: the admin page is always parallel to the SCEP endpoint — append 'mscep_admin/'
            // to it. e.g. https://host/vscep/ -> https://host/vscep/mscep_admin/, and scepca's own
            // /scep/<profile> -> /scep/<profile>/mscep_admin/.
            path = path.EndsWith("/", System.StringComparison.Ordinal) ? path + "mscep_admin/" : path + "/mscep_admin/";
        }
        return new System.UriBuilder(uri) { Path = path, Query = string.Empty }.Uri.ToString();
    }
}

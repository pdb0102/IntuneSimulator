using System;
using System.Net.Http;
using System.Threading.Tasks;
using ScepWright.Crypto;

namespace ScepWright.Core.Transport;

/// <summary>HTTP transport for SCEP operations: builds the query URLs and reads the binary responses.</summary>
public sealed class ScepHttpTransport {
    private readonly HttpClient _http;
    private readonly Uri _base_url;

    /// <summary>Creates a transport against the given base URL with the given request timeout.</summary>
    public ScepHttpTransport(HttpClient http, Uri base_url, TimeSpan timeout) {
        _http = http;
        _base_url = base_url;
        _http.Timeout = timeout;
    }

    private Uri BuildGetUri(string operation, string message) {
        string query;

        query = $"?operation={Uri.EscapeDataString(operation)}";
        if (message.Length > 0) { query += $"&message={Uri.EscapeDataString(message)}"; }
        return new Uri(_base_url + query);
    }

    /// <summary>Issues a GET for the given SCEP operation with the message in the query string.</summary>
    public async Task<ScepResult<byte[]>> GetAsync(string operation, string message) {
        HttpResponseMessage resp;

        try {
            resp = await _http.GetAsync(BuildGetUri(operation, message)).ConfigureAwait(false);
            return await ReadAsync(resp).ConfigureAwait(false);
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    /// <summary>Issues a GET for the given SCEP operation with the message in the query string.</summary>
    public ScepResult<byte[]> Get(string operation, string message) {
        HttpResponseMessage resp;

        try {
            resp = _http.Send(new HttpRequestMessage(HttpMethod.Get, BuildGetUri(operation, message)));
            return Read(resp);
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    /// <summary>POSTs the binary PKI message body for the given SCEP operation.</summary>
    public async Task<ScepResult<byte[]>> PostAsync(string operation, byte[] body) {
        HttpResponseMessage resp;

        try {
            resp = await _http.PostAsync(BuildGetUri(operation, string.Empty), PkiContent(body)).ConfigureAwait(false);
            return await ReadAsync(resp).ConfigureAwait(false);
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    /// <summary>POSTs the binary PKI message body for the given SCEP operation.</summary>
    public ScepResult<byte[]> Post(string operation, byte[] body) {
        HttpRequestMessage req;

        try {
            req = new HttpRequestMessage(HttpMethod.Post, BuildGetUri(operation, string.Empty)) { Content = PkiContent(body) };
            return Read(_http.Send(req));
        } catch (Exception ex) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, ex.Message); }
    }

    private static ByteArrayContent PkiContent(byte[] body) {
        ByteArrayContent content;

        content = new ByteArrayContent(body);
        content.Headers.TryAddWithoutValidation("Content-Type", "application/x-pki-message");
        return content;
    }

    /// <summary>
    /// Returns a friendly description of an HTTP error status. A bare "HTTP 404" tells a non-expert
    /// nothing; it almost always means the SCEP URL path is wrong.
    /// </summary>
    public static string DescribeHttpError(int status) {
        if (status == 404) {
            return "HTTP 404 (Not Found) — the SCEP endpoint path looks wrong; verify the server URL path (commonly /scep, /certsrv/mscep/mscep.dll, or /<app>/pkiclient.exe)";
        }
        return $"HTTP {status}";
    }

    private static ScepResult<byte[]> Read(HttpResponseMessage resp) {
        if (!resp.IsSuccessStatusCode) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, DescribeHttpError((int)resp.StatusCode)); }
        return ScepResult<byte[]>.Ok(resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult());
    }

    private static async Task<ScepResult<byte[]>> ReadAsync(HttpResponseMessage resp) {
        if (!resp.IsSuccessStatusCode) { return ScepResult<byte[]>.Fail(ScepClientResult.NetworkError, DescribeHttpError((int)resp.StatusCode)); }
        return ScepResult<byte[]>.Ok(await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
    }

}

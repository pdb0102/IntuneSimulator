using System.Diagnostics;
using System.Threading;
using ScepWright.Crypto;

namespace ScepWright.Core.Testing;

/// <summary>Simulates a Jamf-style enrollment that polls a PENDING request to completion.</summary>
public static class JamfSimulator {
    /// <summary>
    /// Enrolls, then (if PENDING) polls every <paramref name="poll_interval"/> until the request
    /// completes or <paramref name="max_wait"/> elapses, returning the final result.
    /// </summary>
    public static JamfResult Run(ScepClient client, EnrollRequest request, string issuer_dn,
                                 System.TimeSpan max_wait, System.TimeSpan poll_interval) {
        Stopwatch sw;
        ScepResult<EnrollOutcome> enroll;
        int polls;
        ScepResult<EnrollOutcome> poll;

        sw = Stopwatch.StartNew();
        enroll = client.Enroll(request);
        if (enroll.Status != ScepClientResult.Pending) {
            sw.Stop();
            return new JamfResult(false, enroll.Value?.PkiStatus ?? PkiStatus.Failure, sw.Elapsed, 0, enroll.Value?.Certificate);
        }

        polls = 0;
        while (true) {
            Thread.Sleep(poll_interval);
            polls++;
            poll = client.Poll(issuer_dn, request.Subject, enroll.Value!.TransactionId);
            if (poll.Status != ScepClientResult.Pending) {
                sw.Stop();
                return new JamfResult(false, poll.Value?.PkiStatus ?? PkiStatus.Failure, sw.Elapsed, polls, poll.Value?.Certificate);
            }
            if (sw.Elapsed > max_wait) {
                sw.Stop();
                return new JamfResult(true, PkiStatus.Pending, sw.Elapsed, polls, null);
            }
        }
    }
}

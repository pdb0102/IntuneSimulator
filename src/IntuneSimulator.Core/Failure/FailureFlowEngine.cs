namespace IntuneSimulator.Core.Failure;

public enum FailureFlowMode { Off, Manual, Auto }

/// <summary>Mutable cursor over <see cref="FailureChain.Matrix"/>. Thread-safe.</summary>
public sealed class FailureFlowEngine
{
    private readonly object _gate = new();
    private FailureFlowMode _mode = FailureFlowMode.Off;
    private int _stepIndex = 0;
    private bool _servedCurrent;

    private volatile bool _hardFaults;
    private volatile int _timeoutDelayMs = 30000;

    /// <summary>When true, Timeout/ConnectionRefused are realized as real socket faults (real Kestrel only).</summary>
    public bool HardFaults { get => _hardFaults; set => _hardFaults = value; }
    /// <summary>Delay (ms) used by the Timeout mode when HardFaults is on.</summary>
    public int TimeoutDelayMs { get => _timeoutDelayMs; set => _timeoutDelayMs = value; }

    public FailureFlowMode Mode { get { lock (_gate) return _mode; } set { lock (_gate) { _mode = value; _servedCurrent = false; } } }
    public int StepIndex { get { lock (_gate) return _stepIndex; } }

    public void Reset() { lock (_gate) { _stepIndex = 0; _servedCurrent = false; } }
    public void Advance() { lock (_gate) { if (_stepIndex < FailureChain.Matrix.Count) _stepIndex++; _servedCurrent = false; } }
    public void SetStep(int n) { lock (_gate) { _stepIndex = Math.Clamp(n, 0, FailureChain.Matrix.Count); _servedCurrent = false; } }

    /// <summary>The current cursor step, or null when the matrix is exhausted (everything succeeds).</summary>
    public FailureStep? Current()
    {
        lock (_gate) return _stepIndex < FailureChain.Matrix.Count ? FailureChain.Matrix[_stepIndex] : null;
    }

    /// <summary>Given a chain endpoint id, returns the failure mode to inject for this request, or null to pass through.</summary>
    public FailureMode? ResolveInjection(string endpointId)
    {
        lock (_gate)
        {
            if (_mode == FailureFlowMode.Off) return null;

            // Auto-advance: a new verification starts when the first endpoint is hit again after we served the cursor.
            if (_mode == FailureFlowMode.Auto && endpointId == FailureChain.FirstEndpointId && _servedCurrent)
            {
                if (_stepIndex < FailureChain.Matrix.Count) _stepIndex++;
                _servedCurrent = false;
            }

            if (_stepIndex >= FailureChain.Matrix.Count) return null;
            var cur = FailureChain.Matrix[_stepIndex];
            if (endpointId == cur.EndpointId)
            {
                _servedCurrent = true;
                return cur.Mode;
            }
            return null;
        }
    }

    public object Snapshot()
    {
        lock (_gate)
        {
            var cur = _stepIndex < FailureChain.Matrix.Count ? FailureChain.Matrix[_stepIndex] : null;
            return new
            {
                mode = _mode.ToString(),
                stepIndex = _stepIndex,
                totalSteps = FailureChain.Matrix.Count,
                hardFaults = HardFaults,
                current = cur is null ? null : new { cur.Index, cur.EndpointId, cur.EndpointTitle, mode = cur.Mode.ToString() }
            };
        }
    }
}

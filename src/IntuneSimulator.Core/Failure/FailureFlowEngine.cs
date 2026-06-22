namespace IntuneSimulator.Core.Failure;

/// <summary>Controls how the failure-flow cursor advances through the failure matrix.</summary>
public enum FailureFlowMode
{
    /// <summary>No fault is ever injected; the clean default state.</summary>
    Off,
    /// <summary>Injects the current step's failure; the cursor advances only when explicitly told to.</summary>
    Manual,
    /// <summary>Injects the current step's failure and auto-advances on each new verification attempt.</summary>
    Auto
}

/// <summary>Mutable cursor over <see cref="FailureChain.Matrix"/>. Thread-safe.</summary>
public sealed class FailureFlowEngine
{
    private readonly object _gate = new();
    private FailureFlowMode _mode = FailureFlowMode.Off;
    private int _stepIndex = 0;
    private bool _servedCurrent;

    private volatile bool _hardFaults;
    private volatile int _timeoutDelayMs = 30000;

    /// <summary>Gets or sets whether Timeout/ConnectionRefused are realized as real socket faults (real Kestrel only).</summary>
    public bool HardFaults { get => _hardFaults; set => _hardFaults = value; }
    /// <summary>Gets or sets the delay (ms) used by the Timeout mode when <see cref="HardFaults"/> is on.</summary>
    public int TimeoutDelayMs { get => _timeoutDelayMs; set => _timeoutDelayMs = value; }

    /// <summary>Gets or sets the failure-flow mode; setting it rewinds the served-current flag.</summary>
    public FailureFlowMode Mode { get { lock (_gate) return _mode; } set { lock (_gate) { _mode = value; _servedCurrent = false; } } }
    /// <summary>Gets the current cursor step index into the failure matrix.</summary>
    public int StepIndex { get { lock (_gate) return _stepIndex; } }

    // Three distinct states, by design — `reset` is NOT "disarm":
    //   • Mode == Off (the default)               -> no fault is ever injected. This is the clean slate.
    //   • Mode == Manual/Auto, step 0..N-1        -> inject Matrix[step]'s failure (step 0 = the FIRST failure).
    //   • Mode == Manual/Auto, step == N (count)  -> stepping is on but every endpoint succeeds (happy path).
    // So Reset() rewinds the cursor to the START of the failure walk (step 0 = first failure); it does NOT
    // turn faults off. For a no-fault server set Mode = Off; to exercise the all-succeed path while staying
    // in stepping mode, SetStep(Matrix.Count). This 0-based model is the documented contract.
    /// <summary>Rewinds the cursor to step 0 (the first failure). Does not disarm faults; set <see cref="Mode"/> to Off for that.</summary>
    public void Reset() { lock (_gate) { _stepIndex = 0; _servedCurrent = false; } }
    /// <summary>Advances the cursor to the next step, stopping at the all-succeed step past the end of the matrix.</summary>
    public void Advance() { lock (_gate) { if (_stepIndex < FailureChain.Matrix.Count) _stepIndex++; _servedCurrent = false; } }
    /// <summary>Sets the cursor to the given step, clamped to the valid range (0 through the matrix count).</summary>
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

    /// <summary>Returns a serializable snapshot of the current mode, cursor position, and the failure being injected.</summary>
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

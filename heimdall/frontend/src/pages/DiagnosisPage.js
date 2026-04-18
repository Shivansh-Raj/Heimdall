import React, { useState, useEffect, useCallback, useRef } from 'react';
import KeyPanel    from '../components/KeyPanel';
import Pipeline   from '../components/Pipeline';
import ResultPanel from '../components/ResultPanel';
import MetricsBar  from '../components/MetricsBar';
import AuditLog    from '../components/AuditLog';
import { usePaillier } from '../hooks/usePaillier';
import { fetchModels, predict } from '../utils/api';
import styles from './DiagnosisPage.module.css';

const INITIAL_STEPS = {
  validate:  { status: '', detail: 'Waiting for input...', time: null },
  normalize: { status: '', detail: 'Awaiting step 1...',   time: null },
  encrypt:   { status: '', detail: 'Awaiting step 2...',   time: null },
  infer:     { status: '', detail: 'Awaiting step 3...',   time: null },
  decrypt:   { status: '', detail: 'Awaiting step 4...',   time: null },
};

function now() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

export default function DiagnosisPage() {
  const [models, setModels]         = useState({});
  const [activeModel, setActiveModel] = useState('diabetes');
  const [fieldValues, setFieldValues] = useState({});
  const [steps, setSteps]           = useState(INITIAL_STEPS);
  const [result, setResult]         = useState(null);
  const [metrics, setMetrics]       = useState({ keyBits: 2048 });
  const [log, setLog]               = useState([]);
  const [running, setRunning]       = useState(false);
  const [serverOnline, setServerOnline] = useState(null);

  const { keyState, genKeys, encryptFeatures, decryptAndInterpret } = usePaillier();

  const addLog = useCallback((msg, type = '') => {
    setLog(prev => [...prev, { ts: now(), msg, type }]);
  }, []);

  const setStep = useCallback((id, status, detail, time) => {
    setSteps(prev => ({
      ...prev,
      [id]: { status, detail: detail ?? prev[id].detail, time: time ?? prev[id].time },
    }));
  }, []);

  // Load models from API on mount
  useEffect(() => {
    fetchModels()
      .then(data => {
        setModels(data);
        setServerOnline(true);
        addLog('Connected to Heimdall API server', 'success');
      })
      .catch(() => {
        setServerOnline(false);
        addLog('API server offline — start the backend (uvicorn)', 'error');
      });
  }, [addLog]);

  // Auto-generate keys on mount
  useEffect(() => {
    addLog('Generating 2048-bit Paillier key pair...', 'warn');
    genKeys()
      .then(() => addLog('Key pair generated — private key stored in memory only', 'success'))
      .catch(e => addLog('Key generation failed: ' + e.message, 'error'));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const currentModel = models[activeModel];
  const features = currentModel?.features || [];

  function handleFieldChange(id, value) {
    setFieldValues(prev => ({ ...prev, [id]: value }));
  }

  async function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  async function runPipeline() {
    if (running) return;
    if (!keyState.generated) { addLog('Keys not ready — please wait', 'warn'); return; }
    if (!serverOnline)       { addLog('API server is offline', 'error'); return; }

    // Validate inputs
    const rawValues = features.map(f => parseFloat(fieldValues[f.id] ?? ''));
    const invalid = features.filter((f, i) => isNaN(rawValues[i]));
    if (invalid.length > 0) {
      addLog(`Missing fields: ${invalid.map(f => f.label).join(', ')}`, 'error');
      return;
    }

    setRunning(true);
    setResult(null);
    setSteps(INITIAL_STEPS);
    const t0 = performance.now();

    try {
      // Step 1 — Validate
      setStep('validate', 'active', `Validating ${features.length} input features...`);
      await sleep(150);
      setStep('validate', 'done',
        rawValues.map((v, i) => `${features[i].id}=${v}`).join(', '),
        +(performance.now() - t0).toFixed(1)
      );
      addLog(`Input validated: ${features.length} features`, '');

      // Step 2 — Normalize
      setStep('normalize', 'active', 'Applying min-max normalization [0, 1]...');
      await sleep(150);
      const { encryptedFeatures, normValues, encTimeMs } = encryptFeatures(
        rawValues, features, keyState.publicKey
      );
      setStep('normalize', 'done',
        `Normalized: [${normValues.map(v => v.toFixed(3)).join(', ')}]`,
        +(performance.now() - t0).toFixed(1)
      );
      addLog('Features normalized', '');

      // Step 3 — Encrypt
      setStep('encrypt', 'active', 'Encrypting with Paillier public key...');
      await sleep(100);
      const cipherPreview = encryptedFeatures.map(e => e.ciphertext.slice(0, 12) + '...').join(', ');
      setStep('encrypt', 'done',
        `E(x): ${cipherPreview}`,
        encTimeMs
      );
      addLog(`Paillier encryption done: ${encTimeMs}ms`, 'success');

      // Step 4 — Server inference
      setStep('infer', 'active', 'Sending to server — computing E(y) = Σ wᵢ·E(xᵢ) + b...');
      const inferStart = performance.now();
      const response = await predict(activeModel, keyState.n, encryptedFeatures);
      const inferTimeMs = +(performance.now() - inferStart).toFixed(1);
      const { encrypted_result } = response;

      setStep('infer', 'done',
        `E(y) received: ${encrypted_result.ciphertext.slice(0, 20)}...`,
        inferTimeMs
      );
      addLog(`Encrypted inference: ${inferTimeMs}ms`, 'success');

      // Step 5 — Decrypt
      setStep('decrypt', 'active', 'Decrypting with private key (client-side only)...');
      await sleep(100);
      const { score, probability, risk } = decryptAndInterpret(encrypted_result, keyState.privateKey);
      const totalMs = +(performance.now() - t0).toFixed(1);
      setStep('decrypt', 'done',
        `score=${score.toFixed(4)} → P(disease)=${(probability * 100).toFixed(1)}% → ${risk}`,
        totalMs
      );
      addLog(`Result: ${risk} RISK (${(probability * 100).toFixed(1)}%)`, risk === 'HIGH' ? 'error' : 'success');

      setResult({
        risk,
        probability,
        score,
        modelLabel: currentModel.label,
        encryptedResult: encrypted_result,
        inferenceTimeMs: response.inference_time_ms,
      });
      setMetrics({ keyBits: 2048, encTimeMs, inferTimeMs, totalTimeMs: totalMs });

    } catch (err) {
      addLog('Pipeline error: ' + err.message, 'error');
      setStep('infer', 'error', 'Server error: ' + err.message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className={styles.page}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.logo}>HEIMDALL</div>
        <div className={styles.tagline}>Privacy-Preserving Medical Diagnosis · Paillier HE</div>
        <div className={styles.statusBar}>
          <StatusPill active={keyState.generated}   label={keyState.generating ? 'Keys: Generating...' : 'Keys: Ready'} />
          <StatusPill active={serverOnline === true} label={serverOnline === null ? 'Server: Checking...' : serverOnline ? 'Server: Online' : 'Server: Offline'} danger={serverOnline === false} />
          <StatusPill active label="TLS: Active" />
          <StatusPill active label="PHI: Encrypted" />
        </div>
      </header>

      {serverOnline === false && (
        <div className={styles.offlineBanner}>
          ⚠ Backend offline. Run: <code>cd backend &amp;&amp; uvicorn api.main:app --reload</code>
        </div>
      )}

      <KeyPanel keyState={keyState} onGenerate={genKeys} />

      {/* Model selector */}
      <div className={styles.modelTabs}>
        {Object.entries(models).map(([id, m]) => (
          <button
            key={id}
            className={[styles.tab, activeModel === id ? styles.tabActive : ''].join(' ')}
            onClick={() => { setActiveModel(id); setResult(null); setFieldValues({}); setSteps(INITIAL_STEPS); }}
          >
            {m.label}
            <span className={styles.tabAcc}>{m.accuracy}%</span>
          </button>
        ))}
        {Object.keys(models).length === 0 && (
          <div className={styles.loadingModels}>Loading models from API...</div>
        )}
      </div>

      {/* Input form */}
      {features.length > 0 && (
        <div className={styles.formPanel}>
          <div className={styles.formGrid}>
            {features.map(f => (
              <div key={f.id} className={styles.field}>
                <label className={styles.fieldLabel}>{f.label}</label>
                <input
                  type="number"
                  className={styles.input}
                  placeholder={String((f.min + f.max) / 2)}
                  min={f.min}
                  max={f.max}
                  step="any"
                  value={fieldValues[f.id] ?? ''}
                  onChange={e => handleFieldChange(f.id, e.target.value)}
                />
                {f.hint && <span className={styles.hint}>{f.hint}</span>}
              </div>
            ))}
          </div>
          <button
            className={styles.runBtn}
            onClick={runPipeline}
            disabled={running || !keyState.generated || !serverOnline}
          >
            {running ? '⟳ Running Pipeline...' : '⚡ Encrypt & Predict'}
          </button>
        </div>
      )}

      <Pipeline steps={steps} />
      <ResultPanel result={result} />
      <MetricsBar metrics={metrics} />
      <AuditLog entries={log} />
    </div>
  );
}

function StatusPill({ active, label, danger }) {
  return (
    <div className={[
      styles.pill,
      active  ? styles.pillActive  : '',
      danger  ? styles.pillDanger  : '',
    ].join(' ')}>
      <span className={styles.dot} />
      {label}
    </div>
  );
}

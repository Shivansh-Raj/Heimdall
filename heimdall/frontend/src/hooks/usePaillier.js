/**
 * usePaillier - React hook for client-side Paillier key management.
 * Keys are kept in React state — never persisted or sent to server
 * (except the public key n, which is safe to share).
 */

import { useState, useCallback } from 'react';
import {
  generateKeyPair,
  encryptVector,
  decryptResult,
  normalizeFeature,
  sigmoid,
} from '../utils/crypto';

export function usePaillier() {
  const [keyState, setKeyState] = useState({
    publicKey: null,
    privateKey: null,
    n: null,
    generating: false,
    generated: false,
  });

  const genKeys = useCallback(async () => {
    setKeyState(s => ({ ...s, generating: true }));
    try {
      const { publicKey, privateKey, n } = await generateKeyPair(2048);
      setKeyState({ publicKey, privateKey, n, generating: false, generated: true });
      return { publicKey, privateKey, n };
    } catch (err) {
      setKeyState(s => ({ ...s, generating: false }));
      throw err;
    }
  }, []);

  /**
   * Encrypt raw feature values for a given model spec.
   * Returns { encryptedFeatures, normValues, encTimeMs }
   */
  const encryptFeatures = useCallback((rawValues, modelFeatures, publicKey) => {
    const pk = publicKey || keyState.publicKey;
    if (!pk) throw new Error('Keys not generated yet.');

    const t0 = performance.now();

    // Step 1 — normalize using clinical ranges (MUST match backend mins/maxs)
    const normValues = rawValues.map((v, i) => {
      const min = modelFeatures[i].min;
      const max = modelFeatures[i].max;
      return Math.max(0, Math.min(1, (v - min) / (max - min)));
    });

    console.log('raw values:  ', rawValues);
    console.log('norm values: ', normValues);   // <-- open browser console to verify

    // Step 2 — encrypt normalized values scaled by 1e6
    const encryptedFeatures = normValues.map(v => {
      const scaled = BigInt(Math.round(v * 1_000_000));
      const ciphertext = pk.encrypt(scaled);
      return {
        ciphertext: ciphertext.toString(),
        exponent: -6,
      };
    });

    const encTimeMs = +(performance.now() - t0).toFixed(2);
    return { encryptedFeatures, normValues, encTimeMs };
  }, [keyState.publicKey]);

  /**
   * Decrypt the server's encrypted result and compute probability + risk.
   * Returns { score, probability, risk }
   */
  const decryptAndInterpret = useCallback((encResult, privateKey) => {
    const pk = privateKey || keyState.privateKey;
    if (!pk) throw new Error('Private key not available.');
    // ------------------
    // console.log('=== DECRYPT RESULT ===', { encResult });

    const score = decryptResult(encResult, pk);
    const probability = sigmoid(score);
    const risk = probability > 0.5 ? 'HIGH' : 'LOW';

    console.log('=== DECRYPT RESULT ===', { score, probability, risk });
    return { score, probability, risk };
  }, [keyState.privateKey]);

  return { keyState, genKeys, encryptFeatures, decryptAndInterpret };
}

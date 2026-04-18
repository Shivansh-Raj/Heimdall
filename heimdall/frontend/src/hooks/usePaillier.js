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
    const normValues = rawValues.map((v, i) =>
      normalizeFeature(v, modelFeatures[i].min, modelFeatures[i].max)
    );
    const encryptedFeatures = encryptVector(normValues, pk);
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

    const score = decryptResult(encResult, pk);
    const probability = sigmoid(score);
    const risk = probability > 0.5 ? 'HIGH' : 'LOW';
    return { score, probability, risk };
  }, [keyState.privateKey]);

  return { keyState, genKeys, encryptFeatures, decryptAndInterpret };
}

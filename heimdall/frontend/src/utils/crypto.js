/**
 * Heimdall - Client-Side Paillier Encryption Utility
 *
 * Uses node-paillier-bigint for real cryptographic operations in the browser.
 * The private key NEVER leaves this module — it is never sent to the server.
 *
 * Security model:
 *   - Key generation: client only
 *   - Encryption:     client only (using public key)
 *   - Decryption:     client only (using private key)
 *   - Server sees:    public key n, encrypted ciphertexts, encrypted result
 */

import * as paillierBigint from 'paillier-bigint';

let _publicKey = null;
let _privateKey = null;

/**
 * Generate a fresh Paillier key pair (2048-bit).
 * Stores keys in module scope — never in localStorage or sent over network.
 */
export async function generateKeyPair(bits = 2048) {
  const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(bits);
  _publicKey = publicKey;
  _privateKey = privateKey;
  return {
    n: publicKey.n.toString(),          // safe to share with server
    publicKey,
    privateKey,
  };
}

/**
 * Encrypt a normalized float value.
 * Paillier works on integers, so we scale by 1e6 before encrypting.
 *
 * @param {number} value - Float in range [0, 1] (normalized)
 * @param {object} publicKey - Paillier public key object
 * @returns {{ ciphertext: string, exponent: number }}
 */
export function encryptValue(value, publicKey) {
  const pk = publicKey || _publicKey;
  if (!pk) throw new Error('No public key. Call generateKeyPair() first.');

  // phe (Python) uses integer plaintexts internally.
  // We multiply by 1e6 to preserve 6 decimal places of precision,
  // then the exponent tells the server the scaling factor.
  const SCALE = 1_000_000;
  const scaled = BigInt(Math.round(value * SCALE));

  const ciphertext = pk.encrypt(scaled);
  return {
    ciphertext: ciphertext.toString(),
    exponent: -6,    // matches 1e6 scaling — phe reads this as value * 10^(-6) = original float
  };
}

/**
 * Encrypt a vector of normalized floats.
 */
export function encryptVector(values, publicKey) {
  return values.map(v => encryptValue(v, publicKey));
}

/**
 * Decrypt a ciphertext returned by the server.
 *
 * @param {{ ciphertext: string, exponent: number }} encResult
 * @param {object} privateKey - Paillier private key object
 * @returns {number} - Decrypted float
 */
export function decryptResult(encResult, privateKey) {
  const pk = privateKey || _privateKey;
  if (!pk) throw new Error('No private key.');

  // node-paillier-bigint's decrypt() returns a plaintext BigInt
  // BUT the library expects the ciphertext as a BigInt input
  const cipherBigInt = BigInt(encResult.ciphertext);
  const decrypted = pk.decrypt(cipherBigInt);  // returns BigInt

  console.log('raw decrypted BigInt:', decrypted.toString().slice(0, 40));
  console.log('type:', typeof decrypted);

  // Convert using string to avoid overflow — parse as float directly
  const str = decrypted.toString();
  const isNegative = str.startsWith('-');
  const absStr = isNegative ? str.slice(1) : str;

  // Insert decimal point 6 places from the right (undo 1e6 scaling)
  const padded = absStr.padStart(7, '0');  // ensure at least 7 digits
  const intPart = padded.slice(0, -6) || '0';
  const fracPart = padded.slice(-6);
  const floatStr = `${isNegative ? '-' : ''}${intPart}.${fracPart}`;
  const result = parseFloat(floatStr);

  console.log('=== decryptResult ===', { str, floatStr, result });
  return result;
}

/**
 * Min-max normalize a raw feature value using model-specific ranges.
 */
export function normalizeFeature(value, min, max) {
  const norm = (value - min) / (max - min);
  return Math.max(0, Math.min(1, norm));
}

/**
 * Sigmoid function to convert logit score → probability.
 */
export function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}



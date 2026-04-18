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

import * as paillierBigint from 'node-paillier-bigint';

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
  if (!pk) throw new Error('No public key available. Call generateKeyPair() first.');

  // Scale to integer: multiply by 2^32 to preserve precision
  const SCALE = BigInt(2 ** 32);
  const scaled = BigInt(Math.round(value * Number(SCALE)));

  const ciphertext = pk.encrypt(scaled);
  return {
    ciphertext: ciphertext.toString(),
    exponent: -32,   // tells server the scaling factor (2^32 = 2^(-exponent))
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
  if (!pk) throw new Error('No private key available.');

  const cipherBigInt = BigInt(encResult.ciphertext);
  const decrypted = pk.decrypt(cipherBigInt);

  // Undo the scaling applied during encryption
  // The exponent field from the server tells us the total scaling
  const scale = Math.pow(2, -encResult.exponent);
  return Number(decrypted) / scale;
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

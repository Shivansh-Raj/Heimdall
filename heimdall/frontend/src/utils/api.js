/**
 * Heimdall - API Service
 * Handles all communication with the FastAPI backend.
 */

import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

/**
 * Fetch available models and their feature specs.
 * @returns {Promise<Object>} models dictionary
 */
export async function fetchModels() {
  const { data } = await api.get('/api/models');
  return data.models;
}

/**
 * Submit encrypted features for inference.
 *
 * @param {string} modelId
 * @param {string} publicKeyN  - The public key modulus (shared with server)
 * @param {Array}  encryptedFeatures - [{ciphertext, exponent}, ...]
 * @returns {Promise<Object>} { encrypted_result, inference_time_ms, ... }
 */
export async function predict(modelId, publicKeyN, encryptedFeatures) {
  const { data } = await api.post('/api/predict', {
    model_id: modelId,
    public_key: { n: publicKeyN },
    encrypted_features: encryptedFeatures,
  });
  return data;
}

/**
 * Fetch benchmark stats for a given model.
 * @param {string} modelId
 */
export async function fetchBenchmark(modelId = 'diabetes') {
  const { data } = await api.get(`/api/benchmark?model_id=${modelId}`);
  return data;
}

/**
 * Health check.
 */
export async function healthCheck() {
  const { data } = await api.get('/');
  return data;
}

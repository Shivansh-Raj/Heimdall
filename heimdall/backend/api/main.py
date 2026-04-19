"""
Heimdall - FastAPI Backend
Privacy-Preserving Medical Diagnosis System
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import List, Optional
import time
import logging

from core.encryption import deserialize_public_key, decrypt_value
from core.models import (
    normalize_features,
    encrypted_linear_inference,
    get_model_specs,
    sigmoid,
    MODEL_SPECS,
)
from core.models import TRAINED_WEIGHTS
print("Loaded weights:", {k: v['weights'] for k, v in TRAINED_WEIGHTS.items()})


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("heimdall")

app = FastAPI(
    title="Heimdall API",
    description="Privacy-Preserving Medical Diagnosis via Paillier HE",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class PublicKeyPayload(BaseModel):
    n: str  # Public key modulus as string


class EncryptedFeature(BaseModel):
    ciphertext: str
    exponent: int


class PredictRequest(BaseModel):
    model_id: str
    public_key: PublicKeyPayload
    encrypted_features: List[EncryptedFeature]

    @field_validator("model_id")
    @classmethod
    def validate_model(cls, v):
        if v not in MODEL_SPECS:
            raise ValueError(f"Unknown model_id '{v}'. Valid: {list(MODEL_SPECS.keys())}")
        return v


class PredictResponse(BaseModel):
    model_id: str
    encrypted_result: dict          # {ciphertext, exponent} — never decrypted server-side
    inference_time_ms: float
    server_note: str = "Server never accessed plaintext data."


class ModelsResponse(BaseModel):
    models: dict


class BenchmarkResponse(BaseModel):
    model_id: str
    key_size_bits: int
    n_features: int
    inference_time_ms: float
    note: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "Heimdall", "version": "1.0.0"}


@app.get("/api/models", response_model=ModelsResponse, tags=["Models"])
def list_models():
    """Return available medical models and their feature specifications."""
    return {"models": get_model_specs()}


@app.post("/api/predict", response_model=PredictResponse, tags=["Inference"])
def predict(req: PredictRequest):
    """
    Perform encrypted inference.

    The server:
      1. Reconstructs the public key (no private key involved)
      2. Computes the linear model over ciphertexts using HE operations
      3. Returns the ENCRYPTED result — never decrypts it

    The client decrypts the result with their private key.
    """
    start = time.perf_counter()

    # Reconstruct public key from client-provided n
    try:
        public_key = deserialize_public_key({"n": req.public_key.n})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {e}")

    # Validate feature count
    expected = len(MODEL_SPECS[req.model_id]["features"])
    if len(req.encrypted_features) != expected:
        raise HTTPException(
            status_code=400,
            detail=f"Expected {expected} encrypted features, got {len(req.encrypted_features)}"
        )

    # Perform encrypted inference
    try:
        enc_features = [f.model_dump() for f in req.encrypted_features]
        encrypted_result = encrypted_linear_inference(public_key, enc_features, req.model_id)
    except Exception as e:
        logger.error(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail=f"Inference failed: {e}")

    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info(f"[{req.model_id}] Encrypted inference complete in {elapsed_ms:.2f}ms")

    return PredictResponse(
        model_id=req.model_id,
        encrypted_result=encrypted_result,
        inference_time_ms=round(elapsed_ms, 2),
    )


@app.get("/api/benchmark", response_model=BenchmarkResponse, tags=["Benchmark"])
def benchmark(model_id: str = "diabetes"):
    """
    Run a quick benchmark: generate keys, encrypt features, infer, return timing.
    This uses dummy data — no real patient values.
    """
    if model_id not in MODEL_SPECS:
        raise HTTPException(status_code=400, detail="Unknown model_id")

    import phe as paillier

    start_total = time.perf_counter()
    pub, priv = paillier.generate_paillier_keypair(n_length=2048)

    n_features = len(MODEL_SPECS[model_id]["features"])
    dummy_values = [0.5] * n_features
    enc = [pub.encrypt(v) for v in dummy_values]
    enc_dicts = [{"ciphertext": str(e.ciphertext()), "exponent": e.exponent} for e in enc]

    inf_start = time.perf_counter()
    encrypted_linear_inference(pub, enc_dicts, model_id)
    inf_ms = (time.perf_counter() - inf_start) * 1000

    return BenchmarkResponse(
        model_id=model_id,
        key_size_bits=2048,
        n_features=n_features,
        inference_time_ms=round(inf_ms, 2),
        note="Benchmark uses dummy data. No PHI involved.",
    )

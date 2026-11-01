"""A throwaway OpenID Connect identity provider for trying AgentWarden's sign-in locally.

DEVELOPMENT ONLY. It signs an ID token for any email you ask for, with no password. Never expose it.

    python examples/dev_idp.py                       # serves http://127.0.0.1:9000

Then start AgentWarden pointed at it:

    AGENTWARDEN_OIDC_ISSUER=http://127.0.0.1:9000 AGENTWARDEN_OIDC_AUDIENCE=agentwarden-dev \\
        agentwarden serve

And "sign in" as a demo user:

    curl "http://127.0.0.1:9000/dev/token?email=alice@acme.example"
"""

from __future__ import annotations

import json
import time
import uuid

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Query
from jwt.algorithms import RSAAlgorithm

ISSUER = "http://127.0.0.1:9000"
AUDIENCE = "agentwarden-dev"
KID = "dev-" + uuid.uuid4().hex[:8]
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # new key every run

app = FastAPI(title="AgentWarden dev IdP (development only)")


@app.get("/.well-known/openid-configuration")
def discovery() -> dict[str, object]:
    return {
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
        "response_types_supported": ["id_token"],
    }


@app.get("/jwks")
def jwks() -> dict[str, object]:
    public = json.loads(RSAAlgorithm.to_jwk(KEY.public_key()))
    return {"keys": [{**public, "kid": KID, "use": "sig", "alg": "RS256"}]}


@app.get("/dev/token")
def dev_token(
    email: str = Query(..., max_length=200), minutes: int = Query(10, ge=1, le=60)
) -> dict[str, str]:
    """Mint an ID token for ``email``. This is what makes this IdP unsafe outside development."""
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "dev|" + email.lower(),
        "email": email.lower(),
        "email_verified": True,
        "iat": now,
        "exp": now + minutes * 60,
    }
    return {"id_token": jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9000)

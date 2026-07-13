"""Compatibility patch for pycognito + newer PyJWT."""

from __future__ import annotations

import base64

import jwt
from pycognito import Cognito
from pycognito.exceptions import TokenVerificationException


_PATCH_FLAG = "_emporia_vue_pycognito_verify_token_patched"


def _verify_token(self, token, id_name, token_use):
    """Patched pycognito.Cognito.verify_token.

    pycognito currently passes a str to PyJWT's compute_hash_digest(), but
    modern PyJWT expects bytes. It also compares a bytes-derived at_hash
    against the string claim from the JWT.
    """

    kid = jwt.get_unverified_header(token).get("kid")
    key = self.get_key(kid)

    if key is None:
        raise TokenVerificationException(
            f"Your {id_name!r} token could not be verified "
            f"(key with ID {kid} not found)."
        )

    hmac_key = jwt.api_jwk.PyJWK(key).key
    required_claims = (["aud"] if token_use != "access" else []) + ["iss", "exp"]

    try:
        decoded = jwt.api_jwt.decode_complete(
            token,
            hmac_key,
            algorithms=["RS256"],
            audience=self.client_id if token_use != "access" else None,
            issuer=self.user_pool_url,
            options={
                "require": required_claims,
                "verify_iat": False,
            },
        )
    except jwt.PyJWTError as err:
        raise TokenVerificationException(
            f"Your {id_name!r} token could not be verified ({err})."
        ) from None

    verified = decoded["payload"]
    header = decoded["header"]

    if verified.get("token_use") != token_use:
        raise TokenVerificationException(
            f"Your {id_name!r} token use ({token_use!r}) could not be verified."
        )

    if (iat := verified.get("iat")) is not None:
        try:
            int(iat)
        except ValueError as exception:
            raise TokenVerificationException(
                f"Your {id_name!r} token's iat claim is not a valid integer."
            ) from exception

    if "at_hash" in verified:
        alg_obj = jwt.get_algorithm_by_name(header["alg"])

        access_token = self.access_token
        if isinstance(access_token, str):
            access_token = access_token.encode("ascii")

        digest = alg_obj.compute_hash_digest(access_token)
        at_hash = (
            base64.urlsafe_b64encode(digest[: len(digest) // 2])
            .rstrip(b"=")
            .decode("ascii")
        )

        if at_hash != verified["at_hash"]:
            raise TokenVerificationException(
                "at_hash claim does not match access_token."
            )

    setattr(self, id_name, token)
    setattr(self, f"{token_use}_claims", verified)

    return verified


def patch_pycognito_verify_token() -> None:
    """Patch pycognito once per interpreter session."""
    if getattr(Cognito, _PATCH_FLAG, False):
        return

    Cognito._emporia_vue_original_verify_token = Cognito.verify_token
    Cognito.verify_token = _verify_token
    setattr(Cognito, _PATCH_FLAG, True)

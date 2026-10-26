"""Canonical importable HA Tunnel file adapter."""
from .hat_decoder import HatError, decode_hat, run

__all__ = ["HatError", "decode_hat", "run"]

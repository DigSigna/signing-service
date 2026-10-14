from enum import Enum


class Algorithm(str, Enum):
    RSA = "RSA"
    ECC = "ECC"
    ECDSA = "ECDSA"
    ED25519 = "ED25519"

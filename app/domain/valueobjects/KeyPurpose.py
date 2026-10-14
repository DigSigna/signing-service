from enum import Enum


class KeyPurpose(str, Enum):
    SIGNING = "SIGNING"
    ENCRYPTION = "ENCRYPTION"
    SIGN_AND_ENCRYPT = "SIGN_AND_ENCRYPT"

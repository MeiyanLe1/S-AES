"""S-AES 实验包：核心算法、多重加密、工作模式与 GUI。

算法层不依赖任何 GUI 库，可单独导入用于自测或命令行调用。
"""

from .core import (
    INV_MIX_MATRIX,
    INV_S_BOX,
    MIX_MATRIX,
    S_BOX,
    ValidationError,
    decrypt_block,
    decrypt_block_debug,
    encrypt_block,
    encrypt_block_debug,
    expand_key,
    format_binary,
    format_hex,
    gf_mul,
    parse_flexible,
    parse_hex_value,
)
from .multi import (
    double_decrypt,
    double_encrypt,
    meet_in_the_middle,
    split_key_32,
    triple_decrypt,
    triple_encrypt,
)
from .modes import (
    decrypt_ascii,
    decrypt_cbc,
    encrypt_ascii,
    encrypt_cbc,
    pad,
    tamper_analysis,
    unpad,
)

__all__ = [
    "S_BOX",
    "INV_S_BOX",
    "MIX_MATRIX",
    "INV_MIX_MATRIX",
    "ValidationError",
    "encrypt_block",
    "decrypt_block",
    "encrypt_block_debug",
    "decrypt_block_debug",
    "expand_key",
    "gf_mul",
    "format_binary",
    "format_hex",
    "parse_hex_value",
    "parse_flexible",
    "split_key_32",
    "double_encrypt",
    "double_decrypt",
    "triple_encrypt",
    "triple_decrypt",
    "meet_in_the_middle",
    "pad",
    "unpad",
    "encrypt_ascii",
    "decrypt_ascii",
    "encrypt_cbc",
    "decrypt_cbc",
    "tamper_analysis",
]

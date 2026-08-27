import pytest

from psp2_core_parse.core import ParseError
from psp2_core_parse.symbols import ElfImage


def test_encrypted_or_non_elf_image_is_rejected(tmp_path):
    path = tmp_path / "module.self"
    path.write_bytes(b"SCE\0" + b"\0" * 100)
    with pytest.raises(ParseError, match="decrypt"):
        ElfImage.read(path)

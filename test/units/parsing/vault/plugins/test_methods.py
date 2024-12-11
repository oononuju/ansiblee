from __future__ import annotations

import os
import pytest
import typing as t

from ansible.plugins.loader import vault_loader
from ansible.parsing.vault import VaultSecret, load_vault_method
from ansible.parsing.vault.methods import VaultSecretError

from ..test_decrypt import get_plugin_names

pytestmark = pytest.mark.usefixtures(patch_rot13_import.__name__)
vault_loader.add_directory(os.path.dirname(__file__))


@pytest.mark.parametrize("plugin_name", get_plugin_names())
def test_roundtrip(plugin_name: str) -> None:
    plugin = vault_loader.get(plugin_name)

    data = b'i am some plaintext that should be encrypted'
    password = VaultSecret(b'i am a vault password')

    vaulted_value = plugin.encrypt(data, password, {})

    round_tripped = plugin.decrypt(vaulted_value, password)

    assert data == round_tripped


@pytest.mark.parametrize("plugin_name", get_plugin_names())
def test_failing_options(plugin_name: str) -> None:
    method = load_vault_method(plugin_name)

    with pytest.raises(TypeError):
        method.encrypt(b'blah', VaultSecret(b'blah'), dict(invalid_option="blah"))


@pytest.mark.parametrize("plugin_name, data, secret, options, expected_output", (
    ('aes256', b'input', b'secret', dict(salt="YmFkc2FsdAo="), "3539366434363662363333323436373336343431366633640a3338643032633137393337393365306365663"
                                                               "864363330336331326136346639323566383263396562313562366635303838626336616161393436386563"
                                                               "33340a3961646464313366376533653537613162316563353333316430363266626535"),
    ('v2', b'input', b'toosmall', {}, VaultSecretError),
    ('v2b', b'input', b'toosmall', {}, VaultSecretError),
))
def test_encrypt_options(plugin_name: str, data: bytes, secret: bytes, options: dict[str, t.Any], expected_output: str | type[Exception]) -> None:
    method = load_vault_method(plugin_name)

    vs = VaultSecret(secret)

    if isinstance(expected_output, type) and issubclass(expected_output, Exception):
        with pytest.raises(expected_output):
            method.encrypt(data, vs, options)
    else:
        result = method.encrypt(data, vs, options)

        assert result == expected_output


@pytest.mark.parametrize("plugin_name", get_plugin_names())
def test_incorrect_password(plugin_name: str) -> None:
    method = load_vault_method(plugin_name)

    vs = VaultSecret(b'the actual correct secret')

    ciphertext = method.encrypt(b'plaintext', vs, {})

    with pytest.raises(VaultSecretError):
        method.decrypt(ciphertext, VaultSecret(b'not the correct secret'))

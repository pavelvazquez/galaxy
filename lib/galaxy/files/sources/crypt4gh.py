import base64
import io
import os
from crypt4gh import keys
from crypt4gh.lib import decrypt

from typing import (
    Optional,
    Union,
)

from galaxy.files import OptionalUserContext
from . import (
    FilesSourceOptions,
    FilesSourceProperties,
)
from .ssh import SshFilesSource, SSHFS


class Crypt4ghViaSshFilesSource(SshFilesSource):
    plugin_type = "crypt4gh_via_ssh"

    def _open_fs(self, user_context=None, opts: Optional[FilesSourceOptions] = None):
        props = self._serialization_props(user_context)
        path = props.pop("path")
        self.sec_key = props.pop("sec_key")
        handle = self._get_root_handle(props, opts)
        if path:
            handle = handle.opendir(path)
        return handle

    def _get_root_handle(self, props, opts):
        extra_props: Union[FilesSourceProperties, dict] = opts.extra_props or {} if opts else {}
        return SSHFS(**{**props, **extra_props})

    def _realize_to(
        self,
        source_path: str,
        native_path: str,
        user_context: OptionalUserContext = None,
        opts: Optional[FilesSourceOptions] = None,
    ):

        with open(native_path, "wb") as write_file:
            props = self._serialization_props(user_context)
            _ = props.pop("path")
            sec_key_data = io.BytesIO(base64.b64decode(props.pop("sec_key")))
            assert sec_key_data.read(len(keys.ssh.MAGIC_WORD)) == keys.ssh.MAGIC_WORD
            parsed_sec_key = keys.ssh.parse_private_key(sec_key_data, None)[0]
            file_path = source_path.split("://")[-1].split("/", 1)[1]
            decrypt(
                [(0, parsed_sec_key, None)],
                self._get_root_handle(props, opts)._sftp.open(file_path),
                write_file
            )

__all__ = ("Crypt4ghViaSshFilesSource",)
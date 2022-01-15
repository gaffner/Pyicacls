from typing import Dict
from functools import cached_property

from impacket.dcerpc.v5 import lsad
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.smb3structs import GENERIC_ALL
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import DCERPC_v5

from pyicacls.structs import SID


class Permissions:
    """
    Base class for the permissions getters and setters.
    Can open smb connection and close it.
    """

    def __init__(
        self, ip: str, remote_name: str, username: str, password: str, domain: str
    ) -> None:
        self.sid_to_name: Dict[SID, str] = {
            SID.build_from_string("S-1-1-18"): "NT AUTHORITY\\SYSTEM"
        }

        self.rid_to_name = {
            "544": "BUILTIN\\Administrators",
            "513": "Domain Users",
        }

        self.connection: SMBConnection = SMBConnection(remote_name, ip)
        self.connection.login(username, password, domain)

        self.transport: SMBTransport = None
        self.tid = None
        self.fid = None

    def close_connection(self) -> None:
        """
        Disconnect from the tree id, close the file
        and disconnect from the smb server
        """

        # close policy handle and transport
        lsad.hLsarClose(self.dce_rpc, self.policy_handle)
        self.transport.disconnect()

        # close the smb connection
        self.connection.close()

    def close_file(self):
        """
        close the tree id and file id handles
        """
        if self.fid:
            self.connection.closeFile(self.tid, self.fid)
            self.connection.disconnectTree(self.tid)

    def open_file(self, share_name: str, file_name: str) -> None:
        """
        Open given file name in the share name
        @param share_name: share to connect to
        @param file_name: file to open
        """
        self.tid = self.connection.connectTree(share_name)
        self.fid = self.connection.openFile(
            self.tid, file_name, desiredAccess=GENERIC_ALL
        )

    @cached_property
    def dce_rpc(self) -> DCERPC_v5:
        self.transport = SMBTransport(
            self.connection.getRemoteName(),
            smb_connection=self.connection,
            filename="lsarpc",
        )
        self.transport.connect()
        dce = self.transport.get_dce_rpc()

        return dce

    @cached_property
    def policy_handle(self):
        self.dce_rpc.bind(lsad.MSRPC_UUID_LSAD)
        policy_handle = lsad.hLsarOpenPolicy2(self.dce_rpc, lsad.POLICY_LOOKUP_NAMES)[
            "PolicyHandle"
        ]

        return policy_handle

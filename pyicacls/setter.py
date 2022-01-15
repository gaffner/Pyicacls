"""
PermissionsSetter can give permissions to given file
"""
import struct
from typing import Optional

from impacket.dcerpc.v5 import lsat
from impacket.smb3structs import FileSecInformation

from pyicacls.permissions import Permissions
from pyicacls.structs import (
    SUPPORTED_PERMISSIONS,
    FileNTUser,
    FileNTACE,
    SID,
)


class PermissionsSetter(Permissions):
    def name_to_sid(self, name: str) -> bytes:
        resp = lsat.hLsarLookupNames3(self.dce_rpc, self.policy_handle, [name])

        return resp["TranslatedSids"]["Sids"][0]["Sid"].getData()[
            4:
        ]  # don't include the 'count' attribute

    def permissions_to_ace(
        self, username: str, permissions: Optional[str]
    ) -> FileNTACE:
        """
        Convert the given permissions and user to binary format
        @param username: username to add / remove permissions
        @param permissions: permissions in the icacls format
        """
        access_required = 0x00000000
        if permissions:
            for permission in permissions.split(","):
                try:
                    access_required |= SUPPORTED_PERMISSIONS[permission]
                except KeyError:
                    pass

        sid_bytes = self.name_to_sid(username)
        total_size = 8 + len(sid_bytes)  # nt ace attributes length + sid length

        permissions_as_bytes = (
            struct.pack("<BBHI", 0x00, 0x00, total_size, access_required) + sid_bytes
        )

        return FileNTACE(permissions_as_bytes)

    @staticmethod
    def insert_permission(sec: FileSecInformation, permission: FileNTACE) -> bytes:
        """
        This function will get the current security descriptor, and then
        insert the given permission to it. will follow this logic:
        - if the sid already exists in the current security descriptor,
        find his index and change his access masks.
        - if the sid not exists, insert it on the top of the other permissions.
        this stage is important because unordered set of permissions can cause to
        invalid behaviour.
        @param sec: current security descriptor
        @param permission: new permission to insert. None for delete existing permission.
        """
        ntuser = FileNTUser(sec.rawData[sec["OffsetToDACL"] :])
        ntace = ntuser["Buffer"]

        new_buffer: bytes = b""
        sid_found: bool = False
        delete_mode: bool = (
            permission["SpecificRights"]
            | permission["StandardRights"]
            | permission["GenericRights"]
        ) == 0

        # enumerate the current permissions and search for the given permission sid
        while len(ntace):
            delete_ace: bool = False
            face = FileNTACE(ntace)  # set new FileNTACE
            sid = SID(face["SID"])  # get the DACL SID

            if sid.rawData == permission["SID"]:
                sid_found = True

                # add the new permissions to the current permission
                face["SpecificRights"] |= permission["SpecificRights"]
                face["StandardRights"] |= permission["StandardRights"]
                face["GenericRights"] |= permission["GenericRights"]

                delete_ace = delete_mode

            # permission not contain anything, then we should delete it
            if not delete_ace:
                new_buffer += face.getData()

            ntace = ntace[face["Size"] :]  # slice the buffer

        if sid_found:
            # replace the current buffer in the one containing the new rights
            ntuser["Buffer"] = new_buffer
            ntuser["Size"] = len(new_buffer) + 8  # add the nt user attribute size
            ntuser["NumACEs"] -= 1
        elif not delete_mode:
            # insert the permissions on the top of the other permissions
            ntuser["Size"] += len(
                permission.getData()
            )  # add the nt user attribute size
            ntuser["Buffer"] = permission.getData() + ntuser["Buffer"]
            ntuser["NumACEs"] += 1

        # create the new security descriptor
        owner = sec.rawData[sec["OffsetToOwner"] : sec["OffsetToGroup"]]
        group = sec.rawData[sec["OffsetToGroup"] : sec["OffsetToDACL"]]

        sec_info_blob = sec.getData() + owner + group + ntuser.getData()
        return sec_info_blob

    def set_permissions(
        self, share_name: str, file_name: str, user: str, permissions: Optional[str]
    ) -> bool:
        """
        Add or remove permissions for a given user to the given file
        @param share_name: the share name where the file is to be opened
        @param file_name: file to set permissions to
        @param user: user to edit his permissions. can be sid either.
        @param permissions: permissions in the icacls format (example: R,W,X,D,I).
        NOTE: not all the permission types supported. currently supporting:
        R - read-only access
        W - write-only access
        D - delete access
        X - execute access
        F - full control
        @return: bool. whether the operation succeeded or not
        """
        self.open_file(share_name=share_name, file_name=file_name)

        permission = self.permissions_to_ace(user, permissions)
        result = self.connection._SMBConnection.queryInfo(
            self.tid,
            self.fid,
            fileInfoClass=0,
            infoType=3,
            additionalInformation=0x00000017,
        )

        sec = FileSecInformation(result)
        security_descriptor = self.insert_permission(sec=sec, permission=permission)

        result = self.connection._SMBConnection.setInfo(
            self.tid,
            self.fid,
            fileInfoClass=0,
            infoType=3,
            additionalInformation=0x04,
            inputBlob=security_descriptor,
        )

        # disconnect from server
        self.close_file()

        return result

    def delete_permissions(self, share_name: str, file_name: str, user: str) -> bool:
        """
        Add or remove permissions for a given user to the given file
        @param share_name: the share name where the file is to be opened
        @param file_name: file to set permissions to
        @param user: user to edit his permissions. can be sid either.
        @return: bool. whether the operation succeeded or not
        """
        return True

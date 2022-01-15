"""
PermissionsShower can show the permissions of given file
"""

from typing import List, Dict

from impacket.dcerpc.v5.lsat import LsarLookupSids2Response
from impacket.smb3structs import GENERIC_ALL
from impacket.dcerpc.v5 import lsat
from impacket.smb3structs import FileSecInformation
from pyicacls.structs import SID, FileNTUser, FileNTACE
from pyicacls.attributes import SecurityAttributes
from pyicacls.permissions import Permissions


# Uses to show the permissions of file in
# readable format (inspired by icacls.exe)
class PermissionsGetter(Permissions):
    def set_sid_to_name(self, sids: List[SID], resp: LsarLookupSids2Response) -> None:
        """
        Set the self.sid_to_name dictionary according to the given sids
        :param sids: sids to translate for there names
        :param resp: the response containing the names
        :return: None
        """
        names = [name["Name"] for name in resp["TranslatedNames"]["Names"]]
        for i, name in enumerate(names):
            # should check here if the name is real sid
            if name in ("None", b""):
                name = sids[i]
            rid = name.split("-")[-1]
            if rid in self.rid_to_name:
                self.sid_to_name[SID.build_from_string(name)] = self.rid_to_name[rid]
            elif sids[i] not in self.sid_to_name:
                self.sid_to_name[sids[i]] = name

    def sids_to_names(self, sids: List[SID]) -> None:
        """
        Resolve sid to username using the LSA_LookupSids
        :param sids: list of sids
        :return: list of usernames
        """
        try:
            resp = lsat.hLsarLookupSids2(self.dce_rpc, self.policy_handle, sids)
        except lsat.DCERPCSessionError as session_error:
            resp = session_error.packet

        self.set_sid_to_name(sids, resp)

    def get_security_attributes(self, sec: FileSecInformation) -> SecurityAttributes:
        """
        Get the security information of the given FileSecInformation object
        :param sec: FileSecInformation instance
        :return: SecurityAttributes
        """
        # get owner SID and Group SID
        owner = SID(sec.rawData[sec["OffsetToOwner"] : sec["OffsetToGroup"]])
        group = SID(sec.rawData[sec["OffsetToGroup"] : sec["OffsetToDACL"]])

        self.sids_to_names([owner, group])

        try:
            owner_name = self.sid_to_name[owner]
        except KeyError:
            owner_name = owner

        try:
            group_name = self.sid_to_name[group]
        except KeyError:
            group_name = group
        security_attributes = SecurityAttributes(owner_name, group_name)

        # get all dacl's
        nt = sec.rawData[sec["OffsetToDACL"] :]
        ntuser = FileNTUser(nt)
        ntace = ntuser["Buffer"]

        while len(ntace):
            face = FileNTACE(ntace)  # set new FileNTACE
            sid = SID(face["SID"])  # get the DACL SID
            ntace = ntace[face["Size"] :]  # slice the buffer
            security_attributes.dacls[sid] = face

        self.sids_to_names(list(security_attributes.dacls.keys()))  # ugly

        for sid, permissions in security_attributes.dacls.items():
            try:
                name = self.sid_to_name[sid]
            except KeyError:
                name = sid

            security_attributes.readable_dacls[sid] = f"{name}:{permissions}"

        return security_attributes

    def get_permissions(self, share_name: str, file_name: str) -> SecurityAttributes:
        """
        connect to the given share and get the filename permissions
        :return: SecurityAttributes
        @param share_name: the share name where the file is to be opened
        @param file_name: file to get permissions from
        @return:
        """
        # set the file and tree handles for the given file
        self.open_file(share_name=share_name, file_name=file_name)

        # query the file security information
        result = self.connection._SMBConnection.queryInfo(
            self.tid,
            self.fid,
            fileInfoClass=0,
            infoType=3,
            additionalInformation=0x00000017,
        )
        sec = FileSecInformation(result)

        # get security attributes
        security_attributes = self.get_security_attributes(sec)
        self.close_file()

        return security_attributes


# my dear dubian

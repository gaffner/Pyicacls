import unittest
import mock
import pickle
from unittest.mock import patch

from pyicacls.getter import PermissionsGetter
from impacket.smb3structs import FileSecInformation
from impacket.smbconnection import SMBConnection


class TestPermissionsGetter( unittest.TestCase ):
    @staticmethod
    def get_permissions_getter(sec_blob) -> PermissionsGetter:
        class Patched(mock.MagicMock):
            def queryInfo(self, *args, **kwargs):
                return sec_blob

        with mock.patch('pyicacls.permissions.SMBConnection', new_callable=Patched):
            return PermissionsGetter(
                ip=mock.Mock, remote_name=mock.Mock, username=mock.Mock, password=mock.Mock, domain=mock.Mock
            )

    @mock.patch( 'pyicacls.permissions.SMBTransport')
    @mock.patch('pyicacls.getter.PermissionsGetter.sids_to_names')
    def generic_check_permissions(self, sec_blob, expected_permissions, _, _m):
        permissions_getter = TestPermissionsGetter.get_permissions_getter( sec_blob )
        expected_permissions = pickle.loads(expected_permissions)

        result = permissions_getter.get_permissions(share_name='share', file_name='nice.txt')

        return result == expected_permissions

    def test_home_permissions(self):
        expected_permissions = (b'\x80\x04\x95\xd5\x05\x00\x00\x00\x00\x00\x00\x8c\x13pyicacls.attributes\x94\x8c'
                                b'\x12SecurityAttributes\x94\x93\x94)\x81\x94}\x94('
                                b'\x8c\x05owner\x94\x8c\x10pyicacls.structs\x94\x8c\x03SID\x94\x93\x94)\x81\x94}\x94('
                                b'\x8c\talignment\x94K\x00\x8c\x06fields\x94}\x94('
                                b'\x8c\x08Revision\x94K\x01\x8c\x07NumAuth\x94K\x05\x8c\tAuthority\x94K\x00\x8c'
                                b'\x0eSubauthorities\x94C\x14\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xe9'
                                b'\x03\x00\x00\x94u\x8c\x07rawData\x94C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                                b'\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xe9\x03\x00\x00\x94\x8c\x04data\x94Nub'
                                b'\x8c\x05group\x94h\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x05h\x10K\x00h\x11C\x14\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G'
                                b'\xea\t\x80\x01\x02\x00\x00\x94uh\x13C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                                b'\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\x01\x02\x00\x00\x94h\x15Nub\x8c\x05dacls'
                                b'\x94}\x94(h\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x05h\x10K\x00h\x11C\x14\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G'
                                b'\xea\t\x80\xf4\x01\x00\x00\x94uh\x13C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                                b'\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xf4\x01\x00\x00\x94h\x15Nubh\x06\x8c'
                                b'\tFileNTACE\x94\x93\x94)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'\x8c\x04Type\x94K\x00\x8c\x0bNTACE_Flags\x94K\x00\x8c\x04Size\x94K$\x8c'
                                b'\x0eSpecificRights\x94M\xbf\x01\x8c\x0eStandardRights\x94K\x13\x8c\rGenericRights'
                                b'\x94K\x00\x8c\x04_SID\x94K\x1ch\x07h"uh\x13Ct\x00\x00$\x00\xbf\x01\x13\x00\x01\x05'
                                b'\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xf4\x01'
                                b'\x00\x00\x00\x10$\x00\xff\x01\x1f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00'
                                b'\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xe9\x03\x00\x00\x00\x10\x14\x00\xff\x01\x1f'
                                b'\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x10\x18\x00\xff\x01\x1f'
                                b'\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x94h\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x05h\x10K\x00h\x11C\x14\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G'
                                b'\xea\t\x80\xe9\x03\x00\x00\x94uh\x13C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                                b'\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xe9\x03\x00\x00\x94h\x15Nubh$)\x81\x94'
                                b'}\x94(h\x0bK\x00h\x0c}\x94(h(K\x00h)K\x10h*K$h+M\xff\x01h,'
                                b'K\x1fh-K\x00h.K\x1ch\x07h4uh\x13CP\x00\x10$\x00\xff\x01\x1f\x00\x01\x05\x00\x00\x00'
                                b'\x00\x00\x05\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xe9\x03\x00\x00\x00'
                                b'\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00'
                                b'\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x94h\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x01h\x10K\x00h\x11C\x04\x00\x00\x00\x00\x94uh\x13C\x0c\x01\x01\x00'
                                b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x94h\x15Nubh$)\x81\x94}\x94('
                                b'h\x0bK\x00h\x0c}\x94(h(K\x00h)K\x10h*K\x14h+M\xff\x01h,'
                                b'K\x1fh-K\x00h.K\x0ch\x07h=uh\x13C,'
                                b'\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00'
                                b'\x00\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x94h\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x02h\x10K\x00h\x11C\x08 \x00\x00\x00 '
                                b'\x02\x00\x00\x94uh\x13C\x10\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x94h\x15Nubh$)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94(h('
                                b'K\x00h)K\x10h*K\x18h+M\xff\x01h,'
                                b'K\x1fh-K\x00h.K\x10h\x07hFuh\x13C\x18\x00\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00'
                                b'\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x94h\x15Nubu\x8c\x0ereadable_dacls\x94}\x94('
                                b'h\x1e\x8c<S-1-5-21-4190006963-579503432-2148133447-500:\x08:(R)(D):(W)('
                                b'X)\x94h0\x8c?S-1-5-21-4190006963-579503432-2148133447-1001:(I):(R)(w)(D):('
                                b'F)\x94h9\x8c\x19S-1-1-0:(I):(R)(w)(D):(F)\x94hB\x8c\x1eS-1-2-32-544:(I):(R)(w)(D):('
                                b'F)\x94uub.')
        sec_blob = (b'\x01\x00\x04\x80\x14\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00L\x00\x00\x00\x01\x05\x00\x00\x00'
                    b'\x00\x00\x05\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xe9\x03\x00\x00\x01\x05\x00\x00'
                    b'\x00\x00\x00\x05\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\x01\x02\x00\x00\x02\x00|\x00'
                    b'\x04\x00\x00\x00\x00\x00$\x00\xbf\x01\x13\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00'
                    b'\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xf4\x01\x00\x00\x00\x10$\x00\xff\x01\x1f\x00\x01\x05\x00\x00'
                    b'\x00\x00\x00\x05\x15\x00\x00\x00\xb3n\xbe\xf9H\x85\x8a"G\xea\t\x80\xe9\x03\x00\x00\x00\x10\x14'
                    b'\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x10\x18\x00\xff\x01'
                    b'\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 \x02\x00\x00'
        )

        self.assertEqual(self.generic_check_permissions(sec_blob, expected_permissions), True)

    def test_martin_permissions(self):
        expected_permissions = (b'\x80\x04\x95\xda\x06\x00\x00\x00\x00\x00\x00\x8c\x13pyicacls.attributes\x94\x8c'
                                b'\x12SecurityAttributes\x94\x93\x94)\x81\x94}\x94('
                                b'\x8c\x05owner\x94\x8c\x10pyicacls.structs\x94\x8c\x03SID\x94\x93\x94)\x81\x94}\x94('
                                b'\x8c\talignment\x94K\x00\x8c\x06fields\x94}\x94('
                                b'\x8c\x08Revision\x94K\x01\x8c\x07NumAuth\x94K\x05\x8c\tAuthority\x94K\x00\x8c'
                                b'\x0eSubauthorities\x94C\x14\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cQ'
                                b'\x04\x00\x00\x94u\x8c\x07rawData\x94C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                                b'\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cQ\x04\x00\x00\x94\x8c\x04data\x94Nub'
                                b'\x8c\x05group\x94h\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x05h\x10K\x00h\x11C\x14\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6'
                                b'\xd4f\x95c\x01\x02\x00\x00\x94uh\x13C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                                b'\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95c\x01\x02\x00\x00\x94h\x15Nub\x8c'
                                b'\x05dacls\x94}\x94(h\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x05h\x10K\x00h\x11C\x14\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6'
                                b'\xd4f\x95cU\x04\x00\x00\x94uh\x13C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00'
                                b'\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cU\x04\x00\x00\x94h\x15Nubh\x06\x8c'
                                b'\tFileNTACE\x94\x93\x94)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'\x8c\x04Type\x94K\x00\x8c\x0bNTACE_Flags\x94K\x00\x8c\x04Size\x94K$\x8c'
                                b'\x0eSpecificRights\x94M\x9f\x01\x8c\x0eStandardRights\x94K\x12\x8c\rGenericRights'
                                b'\x94K\x00\x8c\x04_SID\x94K\x1ch\x07h"uh\x13C\x88\x00\x00$\x00\x9f\x01\x12\x00\x01'
                                b'\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cU'
                                b'\x04\x00\x00\x00\x10$\x00\xff\x01\x1f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                                b'\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cQ\x04\x00\x00\x00\x10\x14\x00\xff\x01'
                                b'\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x10\x18\x00\xff\x01'
                                b'\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12'
                                b'\x00\x00\x00\x94h\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x05h\x10K\x00h\x11C\x14\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6'
                                b'\xd4f\x95cQ\x04\x00\x00\x94uh\x13C\x1c\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00'
                                b'\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cQ\x04\x00\x00\x94h\x15Nubh$)\x81\x94}\x94('
                                b'h\x0bK\x00h\x0c}\x94(h(K\x00h)K\x10h*K$h+M\xff\x01h,'
                                b'K\x1fh-K\x00h.K\x1ch\x07h4uh\x13Cd\x00\x10$\x00\xff\x01\x1f\x00\x01\x05\x00\x00\x00'
                                b'\x00\x00\x05\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cQ\x04\x00\x00\x00'
                                b'\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00'
                                b'\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12'
                                b'\x00\x00\x00\x94h\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x01h\x10K\x00h\x11C\x04\x00\x00\x00\x00\x94uh\x13C\x0c\x01\x01\x00'
                                b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x94h\x15Nubh$)\x81\x94}\x94('
                                b'h\x0bK\x00h\x0c}\x94(h(K\x00h)K\x10h*K\x14h+M\xff\x01h,'
                                b'K\x1fh-K\x00h.K\x0ch\x07h=uh\x13C@\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00'
                                b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00'
                                b'\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12'
                                b'\x00\x00\x00\x94h\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x02h\x10K\x00h\x11C\x08 \x00\x00\x00 '
                                b'\x02\x00\x00\x94uh\x13C\x10\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x94h\x15Nubh$)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94(h('
                                b'K\x00h)K\x10h*K\x18h+M\xff\x01h,K\x1fh-K\x00h.K\x10h\x07hFuh\x13C,'
                                b'\x00\x10\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                                b'\x02\x00\x00\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12'
                                b'\x00\x00\x00\x94h\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
                                b'h\x0eK\x01h\x0fK\x01h\x10K\x00h\x11C\x04\x12\x00\x00\x00\x94uh\x13C\x0c\x01\x01\x00'
                                b'\x00\x00\x00\x00\x05\x12\x00\x00\x00\x94h\x15Nubh$)\x81\x94}\x94('
                                b'h\x0bK\x00h\x0c}\x94(h(K\x00h)K\x10h*K\x14h+M\xff\x01h,'
                                b'K\x1fh-K\x00h.K\x0ch\x07hOuh\x13C\x14\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00'
                                b'\x00\x00\x00\x00\x05\x12\x00\x00\x00\x94h\x15Nubu\x8c\x0ereadable_dacls\x94}\x94('
                                b'h\x1e\x8c8S-1-5-21-2221507545-3868804234-1670735572-1109:\x08:(R):('
                                b'W)\x94h0\x8c@S-1-5-21-2221507545-3868804234-1670735572-1105:(I):(R)(w)(D):('
                                b'F)\x94h9\x8c\x19S-1-1-0:(I):(R)(w)(D):(F)\x94hB\x8c\x1eS-1-2-32-544:(I):(R)(w)(D):('
                                b'F)\x94hK\x8c%NT AUTHORITY\\SYSTEM:(I):(R)(w)(D):(F)\x94uub.')
        sec_blob = (b'\x01\x00\x04\x80\x14\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00L\x00\x00\x00\x01\x05\x00\x00\x00'
                    b'\x00\x00\x05\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cQ\x04\x00\x00\x01\x05\x00\x00'
                    b'\x00\x00\x00\x05\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95c\x01\x02\x00\x00\x02\x00'
                    b'\x90\x00\x05\x00\x00\x00\x00\x00$\x00\x9f\x01\x12\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00'
                    b'\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cU\x04\x00\x00\x00\x10$\x00\xff\x01\x1f\x00\x01\x05'
                    b'\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xd9\x83i\x84\x8aD\x99\xe6\xd4f\x95cQ\x04\x00\x00\x00'
                    b'\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x10\x18\x00'
                    b'\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 '
                    b'\x02\x00\x00\x00\x10\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00')
        result = self.generic_check_permissions(sec_blob, expected_permissions)

        self.assertEqual(result, True)

    def test_samba_permissions(self):
        expected_permissions = (
            b'\x80\x04\x95\xf2\x03\x00\x00\x00\x00\x00\x00\x8c\x13pyicacls.attributes\x94\x8c\x12SecurityAttributes'
            b'\x94\x93\x94)\x81\x94}\x94(\x8c\x05owner\x94\x8c\x10pyicacls.structs\x94\x8c\x03SID\x94\x93\x94)\x81'
            b'\x94}\x94(\x8c\talignment\x94K\x00\x8c\x06fields\x94}\x94('
            b'\x8c\x08Revision\x94K\x01\x8c\x07NumAuth\x94K\x02\x8c\tAuthority\x94K\x00\x8c\x0eSubauthorities\x94C'
            b'\x08\x01\x00\x00\x00\x00\x00\x00\x00\x94u\x8c\x07rawData\x94C\x10\x01\x02\x00\x00\x00\x00\x00\x16\x01'
            b'\x00\x00\x00\x00\x00\x00\x00\x94\x8c\x04data\x94Nub\x8c\x05group\x94h\x08)\x81\x94}\x94('
            b'h\x0bK\x00h\x0c}\x94(h\x0eK\x01h\x0fK\x02h\x10K\x00h\x11C\x08\x02\x00\x00\x00\x00\x00\x00\x00\x94uh'
            b'\x13C\x10\x01\x02\x00\x00\x00\x00\x00\x16\x02\x00\x00\x00\x00\x00\x00\x00\x94h\x15Nub\x8c\x05dacls\x94'
            b'}\x94(h\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
            b'h\x0eK\x01h\x0fK\x02h\x10K\x00h\x11C\x08\x01\x00\x00\x00\x00\x00\x00\x00\x94uh\x13C\x10\x01\x02\x00\x00'
            b'\x00\x00\x00\x16\x01\x00\x00\x00\x00\x00\x00\x00\x94h\x15Nubh\x06\x8c\tFileNTACE\x94\x93\x94)\x81\x94'
            b'}\x94(h\x0bK\x00h\x0c}\x94(\x8c\x04Type\x94K\x00\x8c\x0bNTACE_Flags\x94K\x00\x8c\x04Size\x94K\x18\x8c'
            b'\x0eSpecificRights\x94M\xff\x01\x8c\x0eStandardRights\x94K\x1e\x8c\rGenericRights\x94K\x00\x8c\x04_SID'
            b'\x94K\x10h\x07h"uh\x13CD\x00\x00\x18\x00\xff\x01\x1e\x00\x01\x02\x00\x00\x00\x00\x00\x16\x01\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x18\x00\x9f\x01\x12\x00\x01\x02\x00\x00\x00\x00\x00\x16\x02\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x14\x00\x9f\x01\x12\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x94h'
            b'\x15Nubh\x08)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94('
            b'h\x0eK\x01h\x0fK\x02h\x10K\x00h\x11C\x08\x02\x00\x00\x00\x00\x00\x00\x00\x94uh\x13C\x10\x01\x02\x00\x00'
            b'\x00\x00\x00\x16\x02\x00\x00\x00\x00\x00\x00\x00\x94h\x15Nubh$)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94(h('
            b'K\x00h)K\x00h*K\x18h+M\x9f\x01h,K\x12h-K\x00h.K\x10h\x07h4uh\x13C,'
            b'\x00\x00\x18\x00\x9f\x01\x12\x00\x01\x02\x00\x00\x00\x00\x00\x16\x02\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x14\x00\x9f\x01\x12\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x94h\x15Nubh\x08)\x81\x94'
            b'}\x94(h\x0bK\x00h\x0c}\x94(h\x0eK\x01h\x0fK\x01h\x10K\x00h\x11C\x04\x00\x00\x00\x00\x94uh\x13C\x0c\x01'
            b'\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x94h\x15Nubh$)\x81\x94}\x94(h\x0bK\x00h\x0c}\x94(h('
            b'K\x00h)K\x00h*K\x14h+M\x9f\x01h,'
            b'K\x12h-K\x00h.K\x0ch\x07h=uh\x13C\x14\x00\x00\x14\x00\x9f\x01\x12\x00\x01\x01\x00\x00\x00\x00\x00\x01'
            b'\x00\x00\x00\x00\x94h\x15Nubu\x8c\x0ereadable_dacls\x94}\x94(h\x1e\x8c\x16S-1-2-1-0:\x08:(R)(w):('
            b'F)\x94h0\x8c\x13S-1-2-2-0:\x08:(R):(W)\x94h9\x8c\x11S-1-1-0:\x08:(R):(W)\x94uub.'
        )
        sec_blob = (b'\x01\x00\x04\x90\x14\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\x01\x02\x00\x00\x00'
                    b'\x00\x00\x16\x01\x00\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x16\x02\x00\x00\x00'
                    b'\x00\x00\x00\x00\x02\x00L\x00\x03\x00\x00\x00\x00\x00\x18\x00\xff\x01\x1e\x00\x01\x02\x00\x00'
                    b'\x00\x00\x00\x16\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x9f\x01\x12\x00\x01\x02\x00'
                    b'\x00\x00\x00\x00\x16\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x9f\x01\x12\x00\x01\x01'
                    b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00')
        result = self.generic_check_permissions( sec_blob, expected_permissions )

        self.assertEqual(result, True)

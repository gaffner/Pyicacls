from impacket.structure import Structure
import struct

# ACE FLAGS
SMB_ACE_FLAG_OI = 0x1
SMB_ACE_FLAG_CI = 0x2
SMB_ACE_FLAG_IO = 0x8
SMB_ACE_FLAG_NP = 0x4
SMB_ACE_FLAG_I = 0x10

# STANDARD RIGHTS
SEC_INFO_STANDARD_WRITE = 0x8
SEC_INFO_STANDARD_READ = 0x2
SEC_INFO_STANDARD_DELETE = 0x1

# SPECIFIC RIGHTS
SEC_INFO_SPECIFIC_WRITE = 0x116
SEC_INFO_SPECIFIC_EXECUTE = 0x20
SEC_INFO_SPECIFIC_FULL = 0x1FF

# COMBINED RIGHTS
SEC_READ_RIGHT = 0x00120089

SUPPORTED_PERMISSIONS = {
    "R": 0x00120089,
    "W": 0x00100116,
    "D": 0x00110000,
    "X": 0x00000020,
    "F": 0x001F01FF,
}


# # GENERAL VARIABLES
# SID_PREFIX = 'S-'

# NT User (DACL) ACL
class FileNTUser(Structure):
    structure = (
        ("Revision", "<H=1"),
        ("Size", "<H=1"),
        ("NumACEs", "<I=1"),
        ("Buffer", ":"),
    )


# SID
class SID(Structure):
    structure = (
        ("Revision", "<B"),
        ("NumAuth", "<B"),
        ("Authority", "<6B"),
        ("Subauthorities", ":"),
    )

    def __repr__(self):
        n = len(self["Subauthorities"]) / 4
        return "-".join(
            map(
                str,
                ["S", int(self["Revision"]), int(self["NumAuth"])]
                + list(struct.unpack(f"<{int( n )}I", self["Subauthorities"])),
            )
        )

    @staticmethod
    def build_from_string(data):
        items = data.split("-")[1:]  # delete the S prefix
        revision = int(items[0])
        numAuth = int(items[1])
        sub_length = len(items) - 2  # minus the revision and numAuth
        subauthorities = struct.pack(f"<{sub_length}I", *tuple(map(int, items[2:])))
        raw_sid = (
            struct.pack("<2B", revision, numAuth)
            + b"\x00" * 5
            + struct.pack("<B", numAuth)
            + subauthorities
        )
        return SID(raw_sid)

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.__repr__() == other.__repr__()

    def __hash__(self):
        return self.__repr__().__hash__()

    def split(self, *args, **kwargs):
        return self.__str__().split(*args, **kwargs)


# NT ACE
class FileNTACE(Structure):
    structure = (
        ("Type", "<B"),
        ("NTACE_Flags", "<B"),
        ("Size", "<H"),
        ("SpecificRights", "<H"),
        ("StandardRights", "<B"),
        ("GenericRights", "<B"),
        ("_SID", "_-SID", '(self["Size"] - 8)'),
        ("SID", ':=""', SID),
    )

    def __str__(self):
        return (
            f"{self.get_readable_ntace_flags()}:{self.get_readable_standard_rights()}:"
            f"{self.get_readable_specific_rights()}"
        )

    def get_readable_ntace_flags(self) -> str:
        """
        return the NTACE Flags in readable format
        (OI) - object inherit
        (CI) - container inherit
        (IO) - inherit only
        (NP) - don't propagate inherit
        (I) - permission inherited from parent container
        """
        flags = ""
        if self["NTACE_Flags"] & SMB_ACE_FLAG_OI:
            flags += "(OI)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_CI:
            flags += "(CI)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_IO:
            flags += "(IO)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_NP:
            flags += "(NP)"
        if self["NTACE_Flags"] & SMB_ACE_FLAG_I:
            flags += "(I)"

        if flags == "":
            return "\b"  # delete one char (the colons)

        return flags

    def get_readable_standard_rights(self) -> str:
        """
        return the standard rights in readable format
        NOTE: not covering all the standard rights (WRITE DAC and SYNC)
        R - read-only access
        W - write-only access
        D - delete access
        """
        flags = ""
        if self["StandardRights"] & SEC_INFO_STANDARD_READ:
            flags += "(R)"
        if self["StandardRights"] & SEC_INFO_STANDARD_WRITE:
            flags += "(w)"
        if self["StandardRights"] & SEC_INFO_STANDARD_DELETE:
            flags += "(D)"

        return flags

    def get_readable_specific_rights(self) -> str:
        """
        return the specific rights in readable format
        NOTE: not covering all the specific rights (only write, execute, full control)
        W - write access
        X - execute access
        F - full control
        """
        if self["SpecificRights"] & SEC_INFO_SPECIFIC_FULL == SEC_INFO_SPECIFIC_FULL:
            return "(F)"  # Full control, no need to waste time

        flags = ""
        if self["SpecificRights"] & SEC_INFO_SPECIFIC_WRITE == SEC_INFO_SPECIFIC_WRITE:
            flags += "(W)"
        if (
            self["SpecificRights"] & SEC_INFO_SPECIFIC_EXECUTE
            == SEC_INFO_SPECIFIC_EXECUTE
        ):
            flags += "(X)"

        return flags

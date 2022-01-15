from typing import Dict, Union, Optional

from pyicacls.structs import SID


class SecurityAttributes:
    """
    This class represent the security attribute of file
    """

    def __init__(self, owner: str, group: str) -> None:
        self.owner = owner
        self.group = group
        self.dacls: Dict[SID, str] = {}
        self.readable_dacls: Dict[SID, str] = {}  # {mame: dacls}

    def __repr__(self) -> str:

        return (
            f"Owner:\t{self.owner}\n"
            f"Group:\t{self.group}\n"
            f"Dacl's:\t"
            "{}".format(
                "\n        ".join(
                    [str(self.readable_dacls[sid]) for sid in self.readable_dacls]
                )
            )
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __eq__(self, other) -> bool:
        return self.__repr__() == other.__repr__()


# added the dubian

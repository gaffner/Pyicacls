from .getter import PermissionsGetter
from .attributes import SecurityAttributes


def get_permissions(
    remoteName: str,
    ip: str,
    username: str,
    password: str,
    domain: str,
    shareName: str,
    pathName: str,
) -> SecurityAttributes:
    """
    Connect to the target machine and get the permissions of the given file in the given share
    :param string remoteName: name of the remote host, can be its NETBIOS name, IP or *\*SMBSERVER*.  If the later,
           and port is 139, the library will try to get the target's server name.
    :param string ip: target server's remote address (IPv4, IPv6) or FQDN
    :param string username: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for
    :param string shareName: the share name where the file is to be opened
    :param string pathName: the path name to open
    :return: SecurityAttributes
    """
    permissions_shower = PermissionsGetter(
        ip=ip,
        remote_name=remoteName,
        username=username,
        password=password,
        domain=domain,
    )

    return permissions_shower.get_permissions(share_name=shareName, file_name=pathName)


def set_permissions(
    remoteName: str,
    ip: str,
    username: str,
    password: str,
    domain: str,
    shareName: str,
    pathName: str,
    permissions: str,
) -> None:
    """
    Connect to the target machine and set the permissions of the given file to the given permissions
    :param string remoteName: name of the remote host, can be its NETBIOS name, IP or *\*SMBSERVER*.  If the later,
           and port is 139, the library will try to get the target's server name.
    :param string ip: target server's remote address (IPv4, IPv6) or FQDN
    :param string username: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for
    :param string shareName: the share name where the file is to be opened
    :param string pathName: the path name to open
    :param FilePermissions permissions: permissions
    :return: bool
    """
    pass

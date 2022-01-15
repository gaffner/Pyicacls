import argparse
import getpass

from pyicacls.getter import PermissionsGetter
from pyicacls.setter import PermissionsSetter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', action='store', help='ip of the target pc', required=True)
    parser.add_argument('--user', action='store', help='user name to authenticate with', required=True)
    parser.add_argument('--password', action='store', help='password to authenticate with (empty for interactive '
                                                           'typing)', default=None)
    parser.add_argument('--domain', action='store', help='domain of the user (empty for local workgroup)')
    parser.add_argument('--share', action='store', help='share name to connect to', default=None)
    parser.add_argument('--file-path', action='store', help='file path to view / change permissions', required=True)

    parser.add_argument('--target-user', action='store', help='target user to change his permission', default=None)
    parser.add_argument('--permissions', action='store', help='permissions to change in the format of <permission '
                                                              'char>,<permission char>. example: R,W', default=None)

    options = parser.parse_args()

    # interactive typing
    if options.password is None:
        options.password = getpass.getpass()

    if options.domain is None:
        options.domain = '.WORKGROUP'

    # in case of set operation
    if options.target_user and options.permissions:
        setter = PermissionsSetter(options.ip, ".", options.user, options.password, options.domain)
        setter.set_permissions(options.share, options.file_path, options.target_user, options.permissions)
        print(f'Successfully processed {options.file_path}')
    # in case of view operation
    else:
        getter = PermissionsGetter(options.ip, ".", options.user, options.password, options.domain)
        print(getter.get_permissions(options.share, options.file_path))


if __name__ == '__main__':
    main()

from pyicacls.setter import PermissionsSetter
from pyicacls.getter import PermissionsGetter
import mock

@mock.patch( 'pyicacls.permissions.SMBTransport' )
@mock.patch( 'pyicacls.getter.PermissionsGetter.sids_to_names' )
def main(_, _m):
    p = PermissionsGetter('lubuntu', '.', 'martin', 'Password1', 'snickers.local')
    print(p.get_permissions('mymfolder', 'nice.txt'))

if __name__ == '__main__':
    main()

#
# p = PermissionsGetter( 'martinpc.snickers.local', 'martinpc', 'martin', 'Password1', 'snickers.local' )
# print(p.get_permissions('share', 'nice.txt'))

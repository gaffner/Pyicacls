# Pyicacls
A package for simple Windows ACL management, much like the windows icacls binary.
This package can run both on UNIX machines and Windows machines.

## How to use?
For regular IT purposes you can use the script attached in the *pyicacls/example* folder.

```
python examples/icacls.py -h
usage: icacls.py [-h] --ip IP --user USER [--password PASSWORD] [--domain DOMAIN] [--share SHARE] --file-path FILE_PATH [--target-user TARGET_USER]
                 [--permissions PERMISSIONS]

optional arguments:
  -h, --help            show this help message and exit
  --ip IP               ip of the target pc
  --user USER           user name to authenticate with
  --password PASSWORD   password to authenticate with (empty for interactive typing)
  --domain DOMAIN       domain of the user (empty for local workgroup)
  --share SHARE         share name to connect to
  --file-path FILE_PATH
                        file path to view / change permissions
  --target-user TARGET_USER
                        target user to change his permission
  --permissions PERMISSIONS
                        permissions to change in the format of <permission char>,<permission char>. example: R,W 
```

For creating automated scripts and other advanced tasks you can use the *PermissionsGetter* and *PermissionsSetter*.

### To view permissions
```
from pyicacls.getter import PermissionsGetter
s = PermissionsGetter('127.0.0.1', 'MyPc', 'MyUsername', 'MyPassword', 'MyDomain')

s.get_permissions('share', 'file.txt')
```
Example output:
```
Owner:  Home
Group:  Domain Users
Dacl's: Guest:(R):(W)(X)
        Administrator:(R)(D):(W)(X)
        Martin:(I):(R)(w)(D):(F)
        Everyone:(I):(R)(w)(D):(F)
```

### To set permissions
``` { .python }
from pyicacls.setter import PermissionsSetter
s = PermissionsSetter('127.0.0.1', 'MyPc', 'MyUsername', 'MyPassword', 'MyDomain')

s.set_permissions('share', 'file.txt', 'Guest', 'R,W')
```

The output for this operation will be bool - whether the operation succeeded or not.

### To remove permissions
Simply pass `None` for the `permissions` parameter of the `set_permissions` function.
```
s.set_permissions('share', 'file.txt', 'Guest', None)
```
This will remove all permissions of the user ```Guest```.

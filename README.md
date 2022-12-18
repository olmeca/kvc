## KVC 
`kvc` is a password-protectable personal key-value store, 
built for convenience on the command line. Typical usage:
```
keytool -list -keystore mystore.jks -storepass `kvc pwd`
```
Here a value is looked up in `kvc`, with key `pwd` and passed as
the value for command line argument `storepass` of the command
`keytool`. The convenience lies in the fact that: 
* You don't enter the password on the command line, 
  where it would end up in your command history.
* Assuming strong passwords, you don't need to type that,
  or copy that from some place on to the command line.

Additionally you can use it to store shortcuts to often used

### How secure is it?
`kvc` stores your secrets in encrypted form ([TwoFish](https://en.wikipedia.org/wiki/Twofish)) into a file 
called `.kvs` in your home directory. 
You can protect access to `kvs` by setting a password with this command:
```
kvc password
```
You will be asked to enter a password (twice for confirmation).
The effect is that when you call `kvc`, you will be asked for
a password. Subsequent calls will bypass the password input,
for an hour, for your convenience.

### Usage
Adding an entry:
```
user@host$ % kvc -a app1test iQXo59wXy9b80?h
user@host$ %
```
Retrieving an entry:
```
user@host$ % kvs app1test
iQXo59wXy9b80?h
user@host$ %
```
Delete an entry:
```
kvc -d app1test 
user@host$ %
```
Setting a password:
```
user@host$ % kvc password
Please enter KVC password:
Please reenter KVC password:
user@host$ %
```
### Hardcoded encryption key
As stated above, the contents of the `.kvc` file is always
  encrypted. The encryption key used to encrypt/decrypt the
  contents is generated at compile time. Every time you recompile `kvs`,
  a new encryption key will be generated. As a consequence, after each 
recompilation your existing keystore will become inaccessible.
### Export and reimport of KVS contents
  If you want to replace your `kvs` version
  by a newer version, you should first export the contents, and then
  delete the existing store at `~/.kvs`. After installing a newer 
  version you can import the contents
  ```
  user@host$ % kvc export > kvcimport.sh
  user@host$ % rm ~/.kvc
  user@host$ % cp <path-to-new-kvc>/kvc /usr/bin/kvc
  user@host$ % sh kvcimport.sh
  ```
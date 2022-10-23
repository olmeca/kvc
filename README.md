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

### How secure is it?
`kvc` stores your secrets in encrypted form ([TwoFish](https://en.wikipedia.org/wiki/Twofish)) into a file 
called `.kvs` in your home directory. You can protect access
to your secrets by setting a password with this command:
```
kvc kvcpass
```
You will be asked to enter a password (twice for confirmation).
The effect is that when you call `kvc`, you will be asked for
a password. Subsequent calls will bypass the password input,
for an hour, for your convenience.

### Usage
Adding an entry:
```asm
user@host$ % kvc app1test iQXo59wXy9b80?h
user@host$ %
```
Retrieving an entry:
```asm
user@host$ % kvs app1test
iQXo59wXy9b80?h
user@host$ %
```
Delete an entry:
```asm
kvc app1test -
user@host$ %
```
Setting a password:
```asm
user@host$ % kvc kvcpass
Please enter KVC password:
Please reenter KVC password:
user@host$ %
```

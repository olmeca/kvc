import std/strutils, streams, tables, os, twofishencryption, times


const
  helpText = """
  kvs is a simple, file-based key-value store, developed to make
  passwords easily accessible when using a command shell.

  Usage:
    kvs <key> <secret> stores the secret under key <key>
    kvs <key>          prints the secret that was stored under key <key>
    kvs <key> -        removes the secret with key <key> from the store.
    kvs kvspass        protect the key-value store with a password
    kvs exportentries  print for every entry a kvs command for importing
                       into a new store.

  Example:
    # store a password in the key-value store
    kvs pw myverylongandsecurepassword
    # use the stored password on the command line
    keytool -list -keystore mystore -storepass `kvs pw`

  Storage:
    The key-values are stored encrypted into location '~/.kvs'

  Note
  kvs is not a password vault. Access is optionally protected by a password,
  but for convenience subsequent calls are accepted without password for an hour.

  Created by Rudi Angela
  """
  secretsFileName = ".kvs"
  passwordMinLength = 8
  passwordKey = "kvspass"
  exportKey = "exportentries"
  lastLoginKey = "kvslastlogin"
  maxLoginValidityIntervalSecs = 3600

type
  InvalidPasswordError = object of ValueError
  NewPasswordError = object of ValueError
  ValueNotFoundError = object of ValueError

var secrets = newTable[string, string]()
var secretsDirty = false
var authenticationRequired = false

proc showHelp() =
  echo helpText

proc getpass(prompt: cstring) : cstring {.header: "<unistd.h>", importc: "getpass".}

proc storageKey(name: string): string =
  twofishEncryptBase64(name)

proc askPassword(prompt: string): string =
  result = $(getpass(prompt))

proc askNewPassword(): string =
  var pw1 = askPassword("Enter new password:")
  var pw2 = askPassword("Reenter new password:")
  if pw1 != pw2:
    raise newException(NewPasswordError, "Different values entered for new password.")
  elif len(pw1) < passwordMinLength:
    raise newException(NewPasswordError, "Password must be at least 8 characters long.")
  else:
    result = pw1

proc secretsFilePath(): string =
  joinPath(getHomeDir(), secretsFileName)

proc saveSecrets() =
  var outStream: Stream = newFileStream(secretsFilePath(), fmWrite)
  for name, value in secrets.pairs:
    outStream.write("$#:$#\l" % [name, value])
  close(outStream)

proc nowAsSeconds(): int =
  int(toUnix(now().toTime()))

proc readSecrets() =
  if fileExists(secretsFilePath()):
    for line in lines secretsFilePath():
      if len(line) > 0:
        let parts = line.split(":")
        secrets[parts[0]] = parts[1]
      else: discard

proc existsSecret(key: string): bool =
  hasKey(secrets, storageKey(key))

proc getSecret(key: string): string =
  let skey = storageKey(key)
  if hasKey(secrets, skey):
    secrets[skey]
  else:
    raise newException(ValueNotFoundError, "No value found for key '$#'." % key)

proc getDecryptedSecret(key: string): string =
  twofishDecryptBase64(getSecret(key))

proc setSecret(key: string, value: string) =
  let sKey = storageKey(key)
  secretsDirty = true
  if value == "-":
    del(secrets, sKey)
  else:
    let decValue =  if key == passwordKey: twofishDecryptBase64(value) else: value
    secrets[sKey] = twofishEncryptBase64(decValue)

proc isPasswordProtected(): bool =
   existsSecret(passwordKey)

proc validatePassword(prompt: string) =
  if isPasswordProtected():
    let userEntry = askPassword(prompt)
    let encryptedEntry = twofishEncryptBase64(userEntry)
    let encryptedPassword = getSecret(passwordKey)
    if encryptedEntry != encryptedPassword:
      raise newException(InvalidPasswordError, "Wrong password entered.")
    setSecret(lastLoginKey, intToStr(nowAsSeconds()))
  else: discard

proc setPassword() =
  validatePassword("Enter old password:")
  let newPassword = askNewPassword()
  setSecret(passwordKey, newPassword)


proc passwordRecentlyEntered(): bool =
  if hasKey(secrets, storageKey(lastLoginKey)):
    let lastTimeString = getDecryptedSecret(lastLoginKey)
    let lastTime = parseInt(lastTimeString)
    let nowSeconds = nowAsSeconds()
    nowSeconds - lastTime < maxLoginValidityIntervalSecs
  else: false

proc askPasswordIfNeeded() =
  if isPasswordProtected() and (not passwordRecentlyEntered() or authenticationRequired):
    validatePassword("Please enter KVC password:")
  else: discard

proc showSecret(key: string) =
  askPasswordIfNeeded()
  echo getDecryptedSecret(key)

proc exportStore() =
  askPasswordIfNeeded()
  for k, v in secrets.pairs:
    let key = twofishDecryptBase64(k)
    if k != lastLoginKey:
      let value = if key == passwordKey: v else: twofishDecryptBase64(v)
      echo ("kvs $# '$#'" % [key, value])

proc processValue(key: string) =
  if key == passwordKey:
    setPassword()
  elif key == exportKey:
    authenticationRequired = true
    exportStore()
  else:
    showSecret(key)

proc setKeyValue(key: string, value: string) =
  askPasswordIfNeeded()
  setSecret(key, value)

proc main() =
  readSecrets()
  if paramCount() < 1:
    showHelp()
  elif paramCount() == 1:
    processValue(paramStr(1))
  else:
    setKeyValue(paramStr(1), paramStr(2))
  if secretsDirty:
    saveSecrets()

main()
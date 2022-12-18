import std/strutils, std/sequtils, streams, tables, os, parseopt, times, logging, pegs, sugar
import kvs/common, kvs/twofishencryption


const
  helpText = """
  kvs is a simple, file-based key-value store, developed primarily
  to make passwords easily accessible when using a command shell,
  whilst not displaying them on the command line or in its history.
  E.g. "keytool -storepass `kvs pwd1` ..."
  Additionally it can be used as enabler for shortcuts on the command
  line, e.g. "curl `kvs url1`"

  Usage:
    kvs -a <key> <value>   stores the value under key <key>
    kvs -u <key> <value>   updates the value for an existing key
    kvs -d <key>           removes the value with key <key> from the store.
    kvs <key1> <key2>...   prints the values that were stored for the given
                           keys, separated by a space
    kvs password           protect the key-value store with a password
    kvs passtime <minutes> skips requiring a password on subsequent use
                           for the given number of minutes.
    kvs export             print for every entry in the store a kvs command
                           for importing into a new store.

  Example:
    # store a password in the key-value store
    kvs pw myverylongandsecurepassword
    # use the stored password on the command line
    keytool -list -keystore mystore -storepass `kvs pw`

  Storage:
    The key-values are stored encrypted into location '~/.kvs'

  Note
  Use kvs as e disposable cache, to keep passwords hidden from the
  command line history, or to minimize repetitive typing. Do not
  use it as the main storage of your data.

  Created by Rudi Angela
  """
  kvsFileName = ".kvs"
  passwordMinLength = 8
  passwordKey = "_kvspass"
  lastLoginKey = "_kvslastlogin"
  passwordWaivePeriodKey = "_passtime"
  maxLoginValidityIntervalMinutes = 10
  
  passwordCommand = "password"
  exportCommand = "export"
  passtimeCommand = "passtime"
  encryptionEnabled = false

type
  InvalidPasswordError = object of ValueError
  NewPasswordError = object of ValueError
  ValueNotFoundError = object of ValueError
  KeyAlreadyExists = object of ValueError

  UserAction* = enum
    AddAction, UpdateAction, DeleteAction, HelpAction, CmdAction

let 
  digitsPattern = peg"\d+"
  keyPattern = peg"[a-zA-Z] [a-zA-Z0-9_-]+"
  keyValuePattern = peg"{[a-zA-Z0-9_-.]+} '::' {.+} !."
  reservedKeys = [ passwordKey, passwordWaivePeriodKey, lastLoginKey ]

var keyValueStore = newTable[string, string]()
var storeIsDirty = false
var authenticationRequired = false
var userAction = CmdAction
var valueSeparator = " "


proc getpass(prompt: cstring) : cstring {.header: "<unistd.h>", importc: "getpass".}

proc showHelp() =
  echo helpText

proc isReserved(key: string): bool =
  reservedKeys.contains(key)

proc askPassword(prompt: string): string =
  result = $(getpass(prompt))

proc storeFilePath(): string =
  joinPath(getHomeDir(), kvsFileName)


proc writeStore(outStream: Stream) =
  for name, value in keyValueStore.pairs:
    outStream.write("$#::$#\l" % [name, value])

proc saveStore() =
  var outStream = newStringStream()
  writeStore(outStream)
  outStream.setPosition(0)
  let content = outStream.readAll()
  let fileContent = if encryptionEnabled: twofishEncrypt(content) else: content
  writeFile(storeFilePath(), fileContent)
  close(outStream)

proc nowAsSeconds(): int =
  int(toUnix(now().toTime()))


proc readSecrets() =
  if fileExists(storeFilePath()):
    let fileContents = readFile(storeFilePath())
    let contents = if encryptionEnabled: twofishDecrypt(fileContents) else: fileContents
    var inStream = newStringStream(contents)
    var line: string
    while inStream.readLine(line):
      if line =~ keyValuePattern:
        keyValueStore[matches[0]] = matches[1]
      else: discard
    close(inStream)
  else: discard

proc validateKey(key: string) =
  if not (key =~ keyPattern):
    quit("Invalid key: '$#'. Keys start with a letter and may contain letters, digits, dashes and underscores." % key)

proc existsKey(key: string): bool =
  hasKey(keyValueStore, key)

proc getValueForKey(key: string): string =
  if hasKey(keyValueStore, key):
    keyValueStore[key]
  else:
    quit("No value found for key '$#'." % key)

proc setValue(key: string, value: string) =
  debug("setValue '$#' -> '$#'" % [key, value])
  keyValueStore[key] = value
  storeIsDirty = true

proc deleteValue(key: string) =
  keyValueStore.del(key)
  storeIsDirty = true

proc isPasswordProtected(): bool =
   existsKey(passwordKey)

proc getIntValue(key: string, defValue: int): int =
  if existsKey(key):
    parseInt(keyValueStore[key])
  else:
    defValue

proc passwordRecentlyEntered(): bool =
  let lastTimeSecs = getIntValue(lastLoginKey, 0)
  let passTTLminutes = getIntValue(passwordWaivePeriodKey, maxLoginValidityIntervalMinutes)
  let passTTLSecs = passTTLminutes * 60
  let nowSeconds = nowAsSeconds()
  nowSeconds - lastTimeSecs < passTTLSecs

proc validatePassword(prompt: string) =
  if isPasswordProtected():
    let userEntry = askPassword(prompt)
    let storedPassword = getValueForKey(passwordKey)
    if userEntry != storedPassword:
      quit("Wrong password entered.")
    else:
      setValue(lastLoginKey, intToStr(nowAsSeconds()))
  else: discard

proc askPasswordIfNeeded() =
  if isPasswordProtected() and (not passwordRecentlyEntered() or authenticationRequired):
    validatePassword("Please enter KVC password:")
  else: discard


proc addValue(key: string, value: string) =
  validateKey(key)
  askPasswordIfNeeded()
  if not keyValueStore.hasKey(key):
    setValue(key, value)
  else:
    quit("Key '$#' already exists. Please use '-u' to update it." % key)

proc deleteValues(keys: seq[string]) =
  askPasswordIfNeeded()
  for key in keys:
    if not reservedKeys.contains(key):
      deleteValue(key)

proc updateValue(key: string, value: string) =
  validateKey(key)
  askPasswordIfNeeded()
  if keyValueStore.hasKey(key):
    setValue(key, value)
  else:
    quit("Key '$#' does not exist. Please use '-a' to add it.")


proc askNewPassword(): string =
  var pw1 = askPassword("Enter new password:")
  var pw2 = askPassword("Reenter new password:")
  if pw1 != pw2:
    quit("Different values entered for new password.")
  elif len(pw1) < passwordMinLength:
    quit("Password must be at least 8 characters long.")
  else:
    result = pw1

proc setPassword() =
  validatePassword("Enter old password:")
  let newPassword = askNewPassword()
  setValue(passwordKey, newPassword)

proc setPassTime(value: string) =
  if value =~ digitsPattern:
    askPasswordIfNeeded()
    setValue(passwordWaivePeriodKey, value)
  else:
    quit("Invalid value for integer: '$#'" % value)


proc showValuesForKeys(keys: seq[string]) =
  echo keys.map(key => getValueForKey(key)).join(valueSeparator)

proc escapeQuotes(source: string): string =
  replace(source, "'", r"\'")

proc exportStore() =
  askPasswordIfNeeded()
  for key, value in keyValueStore.pairs:
    if not reservedKeys.contains(key):
      echo ("kvs -a $# $#'$#'" % [key, "$", escapeQuotes(value)])

proc readCmdLine(): seq[string] =
  result = @[]
  var cmdLineOptions = initOptParser()
  for kind, key, value in getopt(cmdLineOptions):
    case kind
    of cmdShortOption:
      case key
      of "h":
        userAction = HelpAction
      of "a":
        userAction = AddAction
      of "d":
        userAction = DeleteAction
      of "s":
        valueSeparator = value
      of "u":
        userAction = UpdateAction
      of "D":
        enableLogging()
      else:
        quit("Invalid command option: '$#'" % key)
    of cmdArgument:
      result.add(key)
    else:
        quit("Invalid command option: $#" % key)

proc main() =
  let args = readCmdLine()
  # Only for testing we use a fixed encryption key
  # When creating a release, either comment out or set your own key
  setEncryptionKey("1234567890123456")
  readSecrets()
  case userAction
  of CmdAction:
    authenticationRequired = true
    if len(args) > 0:
      case args[0]
      of passwordCommand:
        debug("cmd: set pwd")
        setPassword()
      of exportCommand:
        debug("cmd: export")
        exportStore()
      of passtimeCommand:
        debug("cmd: set password validity period")
        if len(args) == 2:
          setPassTime(args[1])
      else:
        showValuesForKeys(args)
    else:
      showHelp()
  of AddAction:
    if len(args) == 2:
      addValue(args[0], args[1])
    else:
      quit("Add action (-a) requires two parameters: key and vaue")
  of DeleteAction:
    deleteValues(args)
  of UpdateAction:
    if len(args) == 2:
      updateValue(args[0], args[1])
    else:
      quit("Update action (-u) requires two parameters: key and vaue")
  of HelpAction:
    showHelp()
  if storeIsDirty:
    saveStore()

main()
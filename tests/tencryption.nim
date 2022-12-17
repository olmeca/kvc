import unittest, streams, std/strformat, std/strutils, logging
import kvs/common, kvs/twofishencryption

setKey("1234567890123456")
enableLogging()

suite "twofish":

  test "one":
    let text = "dit is een enorme test"
    let converted = text.twofishEncrypt().twofishDecrypt()
    debug ("result: '$#'" % converted)
    check converted == text
    # check twofishEncryptBase64(text).twofishDecryptBase64() == text
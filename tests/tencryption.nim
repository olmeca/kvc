import unittest, streams, std/strformat, std/strutils, logging
import kvs/common, kvs/twofishencryption

# For unit tests we use a fixed encryption key
setEncryptionKey("1234567890123456")
# enableLogging()

suite "twofish":

  test "smaller than 1 block":
    let text = "dit is een"
    debug ("source: '$#'" % text)
    let converted = text.twofishEncrypt().twofishDecrypt()
    debug ("result: '$#'" % converted)
    check converted == text
    # check twofishEncryptBase64(text).twofishDecryptBase64() == text

  test "exactly 1 block":
    let text = "dit is een goede"
    debug ("source: '$#'" % text)
    let converted = text.twofishEncrypt().twofishDecrypt()
    debug ("result: '$#'" % converted)
    check converted == text
    # check twofishEncryptBase64(text).twofishDecryptBase64() == text

  test "smaller than 2 blocks":
    let text = "dit is een goede test"
    debug ("source: '$#'" % text)
    let converted = text.twofishEncrypt().twofishDecrypt()
    debug ("result: '$#'" % converted)
    check converted == text
    # check twofishEncryptBase64(text).twofishDecryptBase64() == text

  test "exactly 2 blocks":
    let text = "dit is een test 1234567890ABCDEF"
    debug ("source: '$#'" % text)
    let converted = text.twofishEncrypt().twofishDecrypt()
    debug ("result: '$#'" % converted)
    check converted == text
    # check twofishEncryptBase64(text).twofishDecryptBase64() == text

  test "large block":
    let text = "la oaihefwkh w3-nlsd fh;k oKH;hk lw ;oslj wlhwboiugbl pweidsh;weoh grfpqh b72n dotwOHGhg okq 7 iu"
    check twofishEncrypt(text).twofishDecrypt() == text

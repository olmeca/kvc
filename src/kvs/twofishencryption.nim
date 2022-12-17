import std/strutils, std/sequtils, std/base64, std/strformat, std/times
import os, sugar, nimcrypto, streams, logging
import common, byteutils


const xorKey = uint8('_')
const bytesLen = 64
const maxLen = 64
const blockSize = 16
# key size for twofish128
const keySize = 128 div 8
const nChunks: int = 4

# String with length keySize
var keyString = format(now(), "yyMMddHHmmss fff")
var key: array[keySize, byte]
var sourceBlock: array[blockSize, byte]
var destBlock: array[blockSize, byte]

proc copyPadded*(source: string, dest: var openArray[byte]) =
  let lenSrc = len(source)
  let lenDest = len(dest)
  let charSeq = toSeq(source.items)
  for i in 0..lenDest-1:
    dest[i] = if i < lenSrc: byte(charSeq[i]) else: byte(' ')

proc makeEncryptionKey(source: string): array[keySize, byte] =
  let srcLen = source.len
  assert srcLen <= keySize
  copyPadded(source, result)

proc genKeyString(): string =
  let randomString = collect(for k in walkDir(getTempDir()): k.path).join("")
  if randomString.len > keySize: substr(randomString, 0, keySize-1) else: randomString

proc xorbyte(x: byte, y: byte): byte =
  byte( uint8(x) xor uint8(y) )



proc xorBytes(bytes: array[keySize, byte]): array[keySize, byte] =
  for i in bytes.low..bytes.high:
    result[i] = xorbyte(bytes[i], xorKey)


# This key is generated once, at compile time, fixed afterwards
const fixedKey = makeEncryptionKey(genKeyString()).xorBytes()

# This key is used for encryption.
# It is settable only for testing.
var twofishKey = fixedKey


proc setKey*(key: string) =
  twofishKey = key.makeEncryptionKey()

proc toString*(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc twofishEncrypt*(source: string): string =
  debug("2fe source: '$#'" % source)
  let inputLen = len(source)
  let nBlocks = (inputLen div blockSize) + 1
  assert len(source) <= maxLen
  var sourceBytes: array[maxLen, byte]
  var destBytes: array[maxLen, byte]
  copyPadded(source, sourceBytes)
  debug("2fe sbytes: '$#'" % sourceBytes.toHex())
  var tf: twofish128
  init(tf, twofishKey)
  debug("encrypt $# bytes in $# blocks" % [intToStr(inputLen), intToStr(nBlocks)])
  for i in 0..(maxLen div blockSize) - 1:
    let offset = i*blockSize
    copyMem(addr sourceBlock[0], addr sourceBytes[offset], blockSize)
    encrypt(tf, sourceBlock, destBlock)
    debug("encrypt '$#' -> '$#'" % [toHex(sourceBlock), toHex(destBlock)])
    copyMem(addr destBytes[offset], addr destBlock[0], blockSize)
  result = encode(destBytes)
  debug("2fe result: '$#'" % result)


proc twofishDecrypt*(source: string): string =
  debug("2fd source: '$#'" % source)
  var decodedBytes = decode(source)
  let inputLen = len(decodedBytes)
  let nBlocks = (inputLen div blockSize) + 1
  let nBytes = nBlocks * blockSize
  var sourceBytes: array[maxLen, byte]
  copyMem(addr sourceBytes[0], addr decodedBytes[0], len(decodedBytes))
  # padSpaces(sourceBytes)
  debug("2fd sbytes: '$#'" % sourceBytes.toHex())
  var destBytes: array[maxLen, byte]
  var tf: twofish128
  init(tf, twofishKey)
  debug("decrypt $# bytes in $# blocks" % [intToStr(inputLen), intToStr(nBlocks)])
  for i in 0..(maxLen div blockSize) - 1:
    let offset = i*blockSize
    copyMem(addr sourceBlock[0], addr sourceBytes[offset], blockSize)
    decrypt(tf, sourceBlock, destBlock)
    copyMem(addr destBytes[offset], addr destBlock[0], blockSize)
  debug("2fd dbytes: '$#'" % destBytes.toHex())
  result = destBytes.toString().strip()
  debug("2fd result: '$#'" % result)


import std/strutils, std/sequtils, std/base64
import os, sugar, nimcrypto, logging
import common, byteutils


const xorKey = uint8('_')
const blockSize = 16
# key size for twofish128
const keySize = 128 div 8
const nChunks: int = 4

# String with length keySize
var key: array[keySize, byte]
var sourceBlock: array[blockSize, byte]
var destBlock: array[blockSize, byte]

proc copyPadded*(source: string, dest: var openArray[byte]) =
  let lenSrc = len(source)
  let lenDest = len(dest)
  let charSeq = toSeq(source.items)
  # After source is exhausted we copy spaces to dest
  for i in 0..<lenDest:
    dest[i] = if i < lenSrc: byte(charSeq[i]) else: byte(' ')

proc xorbyte(x: byte, y: byte): byte =
  byte( uint8(x) xor uint8(y) )

proc xorBytes(bytes: var array[keySize, byte]) =
  for i in bytes.low..bytes.high:
    bytes[i] = xorbyte(bytes[i], xorKey)

proc makeEncryptionKey(source: string): array[keySize, byte] =
  let srcLen = source.len
  assert srcLen <= keySize
  copyPadded(source, result)
  xorBytes(result)

proc genKeyString(): string =
  let randomString = collect(for k in walkDir(getTempDir()): k.path).join("")
  if randomString.len > keySize: substr(randomString, 0, keySize-1) else: randomString


# This key is generated once, at compile time, fixed afterwards
const fixedKey = makeEncryptionKey(genKeyString())

# This key is used for encryption.
# It is settable only for testing.
var twofishKey = fixedKey


proc setEncryptionKey*(key: string) =
  twofishKey = key.makeEncryptionKey()

proc toString*(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc twofishEncrypt*(source: string): string =
  debug("2fe source: '$#'" % source)
  let inputLen = len(source)
  let nBlocks = (inputLen div blockSize) + (if inputLen mod blockSize > 0: 1 else: 0)
  let nBytes = nBlocks * blockSize
  var sourceBytes = newSeq[byte](nBytes)
  var destBytes = newSeq[byte](nBytes)
  copyPadded(source, sourceBytes)
  debug("2fe sbytes: '$#'" % byteutils.toHex(sourceBytes))
  var tf: twofish128
  init(tf, twofishKey)
  debug("encrypt $# bytes in $# blocks" % [intToStr(inputLen), intToStr(nBlocks)])
  # Encrypt block by block
  for i in 0..<nBlocks:
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
  let nBytes = len(decodedBytes)
  # assert an integer number of blocks in input
  assert nBytes mod blockSize == 0
  let nBlocks = nBytes div blockSize
  var sourceBytes = newSeq[byte](nBytes)
  var destBytes = newSeq[byte](nBytes)
  copyMem(addr sourceBytes[0], addr decodedBytes[0], nBytes)
  # padSpaces(sourceBytes)
  debug("2fd sbytes: '$#'" % byteutils.toHex(sourceBytes))
  var tf: twofish128
  init(tf, twofishKey)
  debug("decrypt $# bytes in $# blocks" % [intToStr(nBytes), intToStr(nBlocks)])
  for i in 0..<nBlocks:
    let offset = i*blockSize
    copyMem(addr sourceBlock[0], addr sourceBytes[offset], blockSize)
    decrypt(tf, sourceBlock, destBlock)
    copyMem(addr destBytes[offset], addr destBlock[0], blockSize)
  debug("2fd dbytes: '$#'" % byteutils.toHex(destBytes))
  result = destBytes.toString().strip()
  debug("2fd result: '$#'" % result)


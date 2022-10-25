import std/strutils, std/sequtils, std/base64, os, sugar, nimcrypto


const xorKey = uint8('_')

proc toBytes(s: string): array[64, byte] =
  let len = s.len
  assert len <= 64
  let sseq = s.toSeq()
  for i in 0..63:
    result[i] = if i < len: byte(sseq[i]) else: 0x00

proc genKey(): string =
  let randomString = collect(for k in walkDir(getTempDir()): k.path).join("")
  if randomString.len > 64: substr(randomString, 0, 63) else: randomString

proc xorbyte(x: byte, y: byte): byte =
  byte( uint8(x) xor uint8(y) )



proc xorBytes(bytes: array[64, byte]): array[64, byte] =
  for i in bytes.low..bytes.high:
    result[i] = xorbyte(bytes[i], xorKey)


const tfKey = genKey().toBytes().xorBytes()


proc twofishEncryptBase64*(source: string): string =
  var sourceBytes = toBytes(source)
  var encryptedBytes = toBytes("")
  var tf: twofish128
  init(tf, tfKey)
  encrypt(tf, addr sourceBytes[0], addr encryptedBytes[0])
  encode(encryptedBytes)


proc twofishDecryptBase64*(source: string): string =
  let base64DecodedBytes = decode(source).toBytes()
  var decryptedBytes = toBytes("")
  var tf: twofish128
  init(tf, tfKey)
  decrypt(tf, base64DecodedBytes, decryptedBytes)
  result.setLen(64)
  var i = 0
  while decryptedBytes[i] != 0x00:
    result[i] = char(decryptedBytes[i])
    inc(i)
  result.setLen(i)


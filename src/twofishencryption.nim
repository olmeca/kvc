import std/sequtils, std/base64, nimcrypto

const tfKey = "Er was een bij te 's Gravenhage"


proc toBytes(s: string): array[64, byte] =
  let len = s.len
  assert len <= 64
  let sseq = s.toSeq()
  for i in 0..63:
    result[i] = if i < len: byte(sseq[i]) else: 0x00


proc twofishEncryptBase64*(source: string): string =
  var sourceBytes = toBytes(source)
  var encryptedBytes = toBytes("")
  var tf: twofish128
  init(tf, toBytes(tfKey))
  encrypt(tf, addr sourceBytes[0], addr encryptedBytes[0])
  encode(encryptedBytes)


proc twofishDecryptBase64*(source: string): string =
  let base64DecodedBytes = decode(source).toBytes()
  var decryptedBytes = toBytes("")
  var tf: twofish128
  init(tf, toBytes(tfKey))
  decrypt(tf, base64DecodedBytes, decryptedBytes)
  result.setLen(64)
  var i = 0
  while decryptedBytes[i] != 0x00:
    result[i] = char(decryptedBytes[i])
    inc(i)
  result.setLen(i)


# Package

version       = "0.1.0"
author        = "olmeca"
description   = "A simple key-value store for command line usage."
license       = "GPL-3.0-or-later"
srcDir        = "src"
bin           = @["kvs"]


# Dependencies

requires "nim >= 1.6.8"
requires "nimcrypto"

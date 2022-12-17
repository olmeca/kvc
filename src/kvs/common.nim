import logging


proc enableLogging*() =
  var logger = newConsoleLogger()
  addHandler(logger)
  setLogFilter(lvlDebug)

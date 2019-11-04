# strinxs
Strings binary, but for dexs and Apks and only show strings matching an expression. It looks recursively in the Apk for dex files (including nested Apks), parses the dex file and only searches the string table [(dex_format)](https://source.android.com/devices/tech/dalvik/dex-format) for strings matching the regular expression.

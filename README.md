# strinxs
Strings binary, but for dexs and Apks and only show strings matching an expression. It looks recursively in the Apk for dex files (including nested Apks), parses the dex file and only searches the string table [(dex_format)](https://source.android.com/devices/tech/dalvik/dex-format) for strings matching the regular expression.
## Usage
- Install the binary (if rust + cargo is installed cargo install --path .)
- strinxs /path/to/apk "[Ss]ome.*[Rr]egular.*[Ee]xpression"

## Frida Hooks
If there are matches in the string table, either for the prototype or the function name, then a frida script with the current timestamp will be created. The script does nothing fancy than hook the function and print some logs.

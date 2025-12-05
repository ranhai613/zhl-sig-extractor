# Extracted Zhl signatures `zhl/`
You can find them in `zhl/`. Feel free to yoink them for Hyperspace work.

In zhl files, functions are sorted in ascending order.

## How to use
Let's say we want to add `FunctionD` to a zhl file in Hyperspace directory.

```cpp
"5589e5538": // unique sig
cleanup __amd64 void Class::FunctionA(); // 0042a600
".538b5918": // unique sig
cleanup __amd64 void Class::FunctionE(); // 0042d190
```

You got full info from this repository.
```cpp
"5589e5538": // unique sig
cleanup __amd64 void Class::FunctionA(); // 0042a600
".578d7c24": // unique sig
cleanup __amd64 void Class::FunctionB(); // 0042a840
".5589e557565": // unique sig
cleanup __amd64 void Class::FunctionC(); // 0042cfa0
".578d7c2408": // unique sig
cleanup __amd64 void Class::FunctionD(); // 0042d040
".538b5918": // unique sig
cleanup __amd64 void Class::FunctionE(); // 0042d190
```

You can just yoink `FunctionD` then insert it to between `FunctionA` and `FunctionE`. Now the zhl file in HS looks like:
```cpp
"5589e5538": // unique sig
cleanup __amd64 void Class::FunctionA(); // 0042a600
".578d7c2408": // unique sig
cleanup __amd64 void Class::FunctionD(); // 0042d040
".538b5918": // unique sig
cleanup __amd64 void Class::FunctionE(); // 0042d190
```

That's it. It should always work as long as the sig of `FunctionD` is unique.

## Unique sig V.S. Non-unique sig
Signatures are labeled as `unique sig` or `non-unique sig` in the form of comments after byte codes.

### Unique sig
Unique sig means a signature that appears only once through the binary. If you add this type of sig as non-chain (without `.`), the hook must work. If you add this as chain (`.`), the hook must work as long as the address of the previous hook is smaller than the target one.

### Non-unique sig
Non-unique sig means a signature that appears multiple times through the binary. It appears due to the extractor failing to generate an unique sig. You need to pay attention to this type of sig. The success of hooking to this function depends on the previous hook. Make sure there is no identical signatures between the previous hook and the target one. Otherwise SigScan will hook that identical signatures instead.

# Zhl Sig Extractor
You can find the script in `ghidra_scripts/ZhlSigExtractor.py`. Run this script within ghidra. You also need to run postprocess script (`snippets/postprocess.py`) after running the ghidra script.

I ran the script for ELF_amd64, ELF_x86 and win32 then stored them within `zhl`.

TODO:
- Extract global variable sigs
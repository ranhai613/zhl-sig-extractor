from glob import glob
import re
from sys import argv

C_CONTAINER_TYPES = ["pair", "vector", "array", "unordered_set", "map", "unordered_map", "unordered_multimap"]
C_CONTAINER_TYPES_ONE = ["vector", "array", "unordered_set"]
C_CONTAINER_TYPES_TWO = ["pair", "map", "unordered_map", "unordered_multimap"]

def remove_const(content: str) -> str:
    if content.startswith("const_"):
        return content[len("const_"):]
    elif content.startswith("_const_"):
        return  content[len("_const_"):]
        
    return content

def preprocess(content: str, platform: str) -> str:
    content = content.replace(" * ", " *") \
                     .replace("std::basic_string<char,_std::char_traits<char>,_std::allocator<char>_>", "std::string") \
                     .replace(", int __in_chrg", "")
    if platform == "win32":
        content = content.replace("static cleanup __amd64 ", "static cleanup __cdecl ") \
                         .replace("cleanup __amd64 ", " __thiscall ")
    elif platform == "elf_x86":
        content = content.replace("cleanup __amd64 ", "cleanup __cdecl ")
    return content

def process_template(content: str) -> str:
    def split_args(content: str) -> list:
        args = []
        current_arg = ""
        bracket_level = 0
        for ch in content:
            if ch == '<':
                bracket_level += 1
            elif ch == '>':
                bracket_level -= 1
            
            if ch == ',' and bracket_level == 0:
                args.append(current_arg.strip())
                current_arg = ""
            else:
                current_arg += ch
        if current_arg:
            args.append(current_arg.strip())
        return args

    def process_type(content: str) -> str:
        if content in C_CONTAINER_TYPES:
            return "std::" + content
        
        TEMPLATE_PATTERN = re.compile(r'([\w:]+)<(.+)>')
        template_match = re.match(TEMPLATE_PATTERN, content)
        if template_match:
            outer_type = template_match.group(1)
            inner_type = template_match.group(2)
            
            types = split_args(inner_type)
            if outer_type.replace("std::", "") in C_CONTAINER_TYPES_ONE:
                types = types[:1] # Only take the first type for single-type containers
            elif outer_type.replace("std::", "") in C_CONTAINER_TYPES_TWO:
                types = types[:2] # Only take the first two types for map types because the latter ones are a hash function or equal function, which we don't need
                for i in range(1, len(types)):
                    if types[i].startswith("_"):
                        types[i] = types[i][1:] # Remove leading underscore for the second type if exists
            processed_inner_type = ", ".join([process_type(inner) for inner in types])
            # Process the outer type and combine
            return f"{process_type(outer_type)}<{processed_inner_type}>"
        return remove_const(content)
        
    ret = ""
    word_buffer = ""
    bracket_content = ""
    bracket_level = 0
    for ch in content:
        assert bracket_level >= 0
        if ch == '<':
            bracket_level += 1
        elif ch == '>':
            bracket_level -= 1
            if bracket_level == 0:
                ret += process_type(f"{word_buffer}{bracket_content}>")
                word_buffer = ""
                bracket_content = ""
                continue
        elif ch.isspace() and bracket_level == 0:
            ret += word_buffer + ch
            word_buffer = ""
            continue
        
        if bracket_level > 0:
            bracket_content += ch
        else:
            word_buffer += ch
    return ret

def rename_functions(content: str) -> str:
    def rename_match(match: re.Match) -> str:
        if match.group(3) == match.group(4):
            return f"{match.group(1)}{match.group(2)}{match.group(3)}::constructor({match.group(5)});"
        elif f"~{match.group(3)}" == match.group(4):
            return f"{match.group(1)}{match.group(2)}{match.group(3)}::destructor({match.group(5)});"
        else:
            return match.group(0)
    
    PROTOTYPE_PATTERN = re.compile(r'(.+)(\s+)(\S+?)::(\S+?)\((.*)\);')
    return re.sub(PROTOTYPE_PATTERN, rename_match, content)

def main(target_dir: str, platform: str = "elf_amd64") -> None:
    for file in glob(target_dir + "/*.zhl"):
        with open(file, "r", encoding="utf-8") as f:
            content = f.read()
        content = preprocess(content, platform)
        content = process_template(content)
        content = rename_functions(content)
        with open(file, "w", encoding="utf-8") as f:
            f.write(content)

if __name__ == "__main__":
    main(argv[1], argv[2])
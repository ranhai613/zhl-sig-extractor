from glob import glob
import re

def remove_const(content: str) -> str:
    if content.startswith("const_"):
        return content[len("const_"):]
    return content

def preprocess(content: str) -> str:
    content = content.replace(" * ", " *") \
                     .replace("std::basic_string<char,_std::char_traits<char>,_std::allocator<char>_>", "std::string")
    return content

def process_template(content: str) -> str:
    def process_vector(vector_content: str) -> str:
        match = re.match(r"(.+),_std::allocator<.+?>_", vector_content)
        assert match is not None
        return f"std::vector<{remove_const(match.group(1))}>"
    
    def process_bracketed(content: str) -> str:
        print("Processing:", content)
        return content
        # TEMPLATE_PATTERN = re.compile(r'([\w:]+)<(.+)>')
        # template_match = re.match(TEMPLATE_PATTERN, type)
        # if template_match:
        #     outer_type = template_match.group(1)
        #     inner_type = template_match.group(2)
        #     if outer_type in C_POINTER_TYPES:
        #         return get_lua_type(inner_type)
            
        #     # Process the inner type recursively
        #     template_rematch = re.match(TEMPLATE_PATTERN, inner_type)
        #     if template_rematch:
        #         processed_inner_type = get_lua_type(inner_type)
        #     else:
        #         types = inner_type.split(",")
        #         if outer_type in C_CONTAINER_TYPES_TWO:
        #             types = types[:2] # Only take the first two types for map types because the latter ones are a hash function or equal function, which we don't need
        #         processed_inner_type = ", ".join([get_lua_type(inner) for inner in types])
        #     # Process the outer type and combine
        #     return f"{get_lua_type(outer_type)}<{processed_inner_type}>"
        
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
                ret += process_bracketed(f"{word_buffer}{bracket_content}>")
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

def main(target_dir: str) -> None:
    for file in glob(target_dir + "/*.zhl"):
        with open(file, "r", encoding="utf-8") as f:
            content = f.read()
        content = preprocess(content)
        content = process_template(content)
        with open(file, "w", encoding="utf-8") as f:
            f.write(content)

if __name__ == "__main__":
    main("zhl/ELF_amd64/1.6.13")
import sys

def generate_template(asm_lines):
    code = "\n".join(asm_lines)
    
    template = f"""
    Analyze the following x86-64 assembly code.
    Identify the purpose of the function, any potential bugs (like buffer overflows),
    and list any interesting system calls or library functions used.

    --- ASSEMBLY ---
{code}
    --- END ASSEMBLY ---

    Analysis:
    """
    return template

def main():
    print("RE-Tools Python Prompt Helper")
    
    # Sample assembly lines
    sample_asm = [
        "0x1000: push rbp",
        "0x1001: mov rbp, rsp",
        "0x1004: mov eax, 0x1",
        "0x1009: pop rbp",
        "0x100a: ret",
    ]
    
    prompt = generate_template(sample_asm)
    print("\n--- Generated Prompt Template ---")
    print(prompt)

if __name__ == "__main__":
    main()
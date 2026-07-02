import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find \multicolumn{X}{Y}{Text} where Text does not start with \textbf
    def repl(match):
        m1 = match.group(1) # {1}
        m2 = match.group(2) # {c}
        text = match.group(3)
        if not text.startswith('\\textbf{'):
            text = f"\\textbf{{{text}}}"
        return f"\\multicolumn{m1}{m2}{{{text}}}"

    new_content = re.sub(r'\\multicolumn(\{[^}]+\})(\{[^}]+\})\{([^{}]+)\}', repl, content)
    
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {filepath}")

for root, _, files in os.walk('.'):
    for file in files:
        if file.endswith('.tex'):
            process_file(os.path.join(root, file))


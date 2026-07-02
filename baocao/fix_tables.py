import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find all longtable blocks
    def repl_longtable(match):
        pre_format = match.group(1) # '{|l|l|}'
        new_format = pre_format.replace('|', '')
        
        body = match.group(2)
        
        # If the table uses standard headers (\endhead, \endlastfoot)
        if '\\endlastfoot' in body or '\\endhead' in body:
            # Split body at \endlastfoot (or \endhead if no \endlastfoot)
            if '\\endlastfoot' in body:
                parts = body.split('\\endlastfoot')
                head_part = parts[0] + '\\endlastfoot'
                data_part = parts[1]
            else:
                parts = body.split('\\endhead')
                head_part = parts[0] + '\\endhead'
                data_part = parts[1]
            
            # 1. Remove horizontal rules in data_part
            data_part = re.sub(r'^\s*\\midrule\s*$', '', data_part, flags=re.MULTILINE)
            data_part = re.sub(r'^\s*\\hline\s*$', '', data_part, flags=re.MULTILINE)
            
            # 2. Remove \textbf{} from data_part
            data_part = re.sub(r'\\textbf{([^}]+)}', r'\1', data_part)
            
            new_body = head_part + data_part
        else:
            # Handle Tu_viet_tat.tex format (simple format)
            # Find the first header row: ... \\ \hline
            # We will manually rewrite it if it's Tu_viet_tat.tex
            lines = body.split('\n')
            new_lines = []
            header_done = False
            for line in lines:
                if '\\hline' in line:
                    if not header_done:
                        new_lines.append('\\midrule') # after header
                    # else skip \hline in body
                elif '\\textbf' in line and not header_done:
                    new_lines.append(line)
                    header_done = True
                else:
                    # remove textbf in body
                    line = re.sub(r'\\textbf{([^}]+)}', r'\1', line)
                    new_lines.append(line)
            
            # insert toprule at the beginning and bottomrule at the end
            new_lines.insert(0, '\\toprule')
            new_lines.append('\\bottomrule')
            
            new_body = '\n'.join(new_lines)

        return f'\\begin{{longtable}}{new_format}{new_body}\\end{{longtable}}'

    new_content = re.sub(r'\\begin{longtable}(\{[^}]*\})(.*?)\\end{longtable}', repl_longtable, content, flags=re.DOTALL)
    
    # Optional: also handle \begin{tabular} just in case
    # No tabular found based on my previous search, but let's be safe.
    
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {filepath}")

for root, _, files in os.walk('.'):
    for file in files:
        if file.endswith('.tex'):
            process_file(os.path.join(root, file))


import os
import re
import glob

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Regex to match a longtable environment
    # We'll use a relatively simple state machine approach since regex for LaTeX can be brittle.
    
    lines = content.split('\n')
    new_lines = []
    
    in_longtable = False
    in_firsthead = False
    in_head = False
    
    current_caption = ""
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        if r'\begin{longtable}' in line:
            in_longtable = True
            current_caption = ""
            new_lines.append(line)
        elif r'\end{longtable}' in line:
            in_longtable = False
            new_lines.append(line)
        elif in_longtable:
            # Look for caption before endfirsthead
            if r'\caption' in line and not in_head:
                # Extract caption text
                # It can be \caption{...} or \caption[...]{...}
                m = re.search(r'\\caption(?:\[.*?\])?\{([^}]+)\}', line)
                if m:
                    current_caption = m.group(1)
            
            if r'\endfirsthead' in line:
                in_head = True
                new_lines.append(line)
            elif r'\endhead' in line:
                in_head = False
                new_lines.append(line)
            elif in_head:
                # We are in the \endfirsthead ... \endhead block.
                # If we see \toprule, and we haven't injected the caption yet, inject it.
                if r'\toprule' in line and current_caption:
                    # check if previous lines already have the tiếp theo caption
                    if not any('(tiếp theo)' in l.lower() for l in new_lines[-5:]):
                        new_lines.append(f'        \\caption[]{{{current_caption} (tiếp theo)}} \\\\')
                    new_lines.append(line)
                    current_caption = "" # prevent injecting again
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
            
        i += 1
        
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))

for d in ['/home/chat-server/baocao/Chuong/2_Phan_tich_thiet_ke', '/home/chat-server/baocao/Chuong/3_Trien_khai_danh_gia']:
    for f in glob.glob(d + '/*.tex'):
        print(f"Processing {f}...")
        process_file(f)

print("Done.")

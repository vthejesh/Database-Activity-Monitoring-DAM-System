import os
import re

glass_css = """:root {
  --bg: #030712; --surface: rgba(17,24,39,0.6); --card: rgba(31,41,55,0.3); --border: rgba(75,85,99,0.4);
  --accent: #38bdf8; --accent2: #818cf8; --red: #ef4444; --green: #10b981;
  --amber: #f59e0b; --text: #f9fafb; --muted: #9ca3af;
  --font: 'Outfit', sans-serif; --mono: 'JetBrains Mono', monospace;
}
body { background: var(--bg); color: var(--text); font-family: var(--font); }
"""

templates_dir = "templates"
for filename in os.listdir(templates_dir):
    if filename.endswith(".html") and filename not in ("login.html", "dashboard_admin.html"):
        filepath = os.path.join(templates_dir, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace the old root variables block
        content = re.sub(r':root\s*\{[^}]*\}', glass_css, content, count=1)
        
        # Replace the font links
        content = re.sub(r'<link href="https://fonts.googleapis.com[^>]+>', 
                         '<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Outfit:wght@300;400;500;600&display=swap" rel="stylesheet">', 
                         content)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
            
print("CSS updated successfully across all templates.")

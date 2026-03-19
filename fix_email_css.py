import re

with open(r'd:\Phishing Website\Phishing Website Detector\static\css\email-scanner.css', 'r', encoding='utf-8') as f:
    css = f.read()

# Make replacements
r = css
r = r.replace('background: rgba(30, 41, 59, 0.5);', 'background: var(--glass-bg);')
r = r.replace('border: 1px solid rgba(255, 255, 255, 0.1);', 'border: 1px solid var(--glass-border);')
r = r.replace('backdrop-filter: blur(10px);', 'backdrop-filter: var(--glass-blur);')
r = r.replace('background: rgba(15, 23, 42, 0.8);', 'background: var(--color-bg-elevated);')
r = r.replace('border: 1px solid rgba(255, 255, 255, 0.15);', 'border: 1px solid var(--glass-border);')
r = r.replace('color: #e2e8f0;', 'color: var(--text-heading-primary);')
r = r.replace('color: #64748b;', 'color: var(--text-muted);')
r = r.replace('background: rgba(255, 255, 255, 0.1);', 'background: var(--glass-border);')
r = r.replace('color: #94a3b8;', 'color: var(--text-metadata);')
r = r.replace('background: rgba(30, 41, 59, 0.7);', 'background: var(--glass-bg);')
r = r.replace('background: rgba(15, 23, 42, 0.5);', 'background: var(--color-bg-elevated);')
r = r.replace('border-bottom: 1px solid rgba(255, 255, 255, 0.1);', 'border-bottom: 1px solid var(--glass-border);')
r = r.replace('border-bottom: 1px solid rgba(255, 255, 255, 0.05);', 'border-bottom: 1px solid var(--glass-border);')
r = r.replace('border-top: 1px solid rgba(255, 255, 255, 0.05);', 'border-top: 1px solid var(--glass-border);')
r = r.replace('color: white;', 'color: #fff;')
r = r.replace('color: #cbd5e1;', 'color: var(--text-body);')

# Fix dark mode override block
r = re.sub(r'body\.dark-mode \.email-input-section \{[^\}]+\}', '', r)
r = re.sub(r'body\.dark-mode \.email-input-section textarea \{[^\}]+\}', '', r)
# Remove empty comment block and Dark Mode Adjustments header
r = re.sub(r'/\* ─+\s*\n\s*DARK MODE ADJUSTMENTS\s*\n\s*─+ \*/\s*\n+', '', r)

with open(r'd:\Phishing Website\Phishing Website Detector\static\css\email-scanner.css', 'w', encoding='utf-8') as f:
    f.write(r)

print('Updated email-scanner.css successfully!')

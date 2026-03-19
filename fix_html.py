import re
import os

def update_file(filepath):
    print(f"Updating {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Wrap <input type="password"> in the UI to have an eye toggle SVG
    def repl(m):
        full_match = m.group(0)
        id_match = re.search(r'id="([^"]+)"', full_match)
        input_id = id_match.group(1) if id_match else 'password'
        
        # Add pr-10 for padding on right so text doesn't hide behind icon
        input_str = full_match
        if 'px-4' in input_str and 'pr-10' not in input_str:
            input_str = input_str.replace('px-4', 'px-4 pr-10')
            
        replacement = f"""<div class="relative">
                        {input_str}
                        <button type="button" class="absolute inset-y-0 right-0 px-3 flex items-center text-gray-400 hover:text-white" onclick="togglePassword('{input_id}')">
                            <svg id="eye-icon-{input_id}" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                            </svg>
                        </button>
                    </div>"""
        return replacement

    content = re.sub(r'<input[^>]+type="password"[^>]*>', repl, content)
    
    # Add JS script just before </body>
    js_script = """
    <script>
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const icon = document.getElementById('eye-icon-' + inputId);
            if (input.type === 'password') {
                input.type = 'text';
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />';
            } else {
                input.type = 'password';
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />';
            }
        }
    </script>
</body>"""
    if "togglePassword" not in content:
        content = content.replace("</body>", js_script)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print("Updated successfully")

update_file(r"ThreatLoom\dashboard\templates\login.html")
update_file(r"ThreatLoom\dashboard\templates\reset_password.html")

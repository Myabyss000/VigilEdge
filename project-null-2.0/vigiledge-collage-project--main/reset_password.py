
import json
import os
import sys
from pathlib import Path

def reset_password(new_password):
    base_dir = Path(__file__).parent
    config_dir = base_dir / "VigilEdge" / "waf" / "config"
    settings_file = config_dir / "waf_settings.json"
    
    print(f"Target: {settings_file}")

    if not settings_file.exists():
        print(f"❌ Error: Settings file not found at {settings_file}")
        return

    try:
        # Read
        with open(settings_file, 'r') as f:
            data = json.load(f)
        
        # Update
        if "authentication" not in data:
            data["authentication"] = {}
            
        old_pass = data["authentication"].get("admin_password", "CHECKSUM_NONE")
        data["authentication"]["admin_password"] = new_password
        
        # Write
        with open(settings_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        print("-" * 50)
        print(f"✅ Success! Password manually reset.")
        print(f"Old Password: {old_pass}")
        print(f"New Password: {new_password}")
        print("-" * 50)
        print("Please restart the server to ensure changes are loaded.")
        
    except Exception as e:
        print(f"❌ Failed to write file: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python reset_password.py <new_password>")
        print(" defaulting to 'admin123'")
        reset_password("admin123")
    else:
        reset_password(sys.argv[1])

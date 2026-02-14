
import json
import pyotp
import qrcode
import os
import sys
from pathlib import Path

def setup_2fa():
    print("="*60)
    print("🔒 VigilEdge WAF - 2FA Setup")
    print("="*60)
    
    # 1. Generate Secret
    # Base32 secret for TOTP (Time-based One-Time Password)
    secret = pyotp.random_base32()
    print(f"\n🔑 Generated Secret Key: {secret}")
    print("(You can manually enter this if you can't scan the QR code)")
    
    # 2. Generate QR Code
    # URI format: otpauth://totp/Label?secret=SECRET&issuer=Issuer
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name="Admin", 
        issuer_name="VigilEdge WAF"
    )
    
    # Generate QR image for terminal or file
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.print_ascii(invert=True)
    
    # Also save as image for easier scanning
    img = qrcode.make(uri)
    img_path = Path("2fa_qr.png")
    img.save(img_path)
    print(f"\n📸 QR Code image saved to: {img_path.absolute()}")
    print("Scan this with Google Authenticator or Authy app.")
    
    # 3. Save to Settings
    base_dir = Path(__file__).parent
    settings_file = base_dir / "VigilEdge" / "waf" / "config" / "waf_settings.json"
    
    try:
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                settings = json.load(f)
        else:
            settings = {}
            
        if "authentication" not in settings:
            settings["authentication"] = {}
            
        # Verify user wants to proceed
        confirm = input("\n⚠️  Do you want to enable 2FA with this key? (y/n): ")
        if confirm.lower() != 'y':
            print("❌ Setup cancelled.")
            return
            
        settings["authentication"]["totp_secret"] = secret
        settings["authentication"]["2fa_enabled"] = True
        
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
            
        print(f"\n✅ Success! 2FA enabled in {settings_file}")
        print("You can now use Google Authenticator to reset your password.")
        
    except Exception as e:
        print(f"\n❌ Error saving settings: {e}")

if __name__ == "__main__":
    setup_2fa()

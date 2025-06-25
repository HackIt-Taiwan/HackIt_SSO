#!/usr/bin/env python3
"""
Static Assets Version Updater for HackIt SSO

This script automatically updates the STATIC_VERSION in the configuration
to force browser cache invalidation when static assets (CSS/JS) are updated.

Usage:
    python update_version.py           # Use current date (YYYYMMDD)
    python update_version.py v1.2.3    # Use custom version string
    python update_version.py --help    # Show help
"""

import re
import sys
from datetime import datetime
from pathlib import Path


def get_current_version():
    """Read current version from config.py"""
    config_path = Path("app/core/config.py")
    if not config_path.exists():
        print("❌ Error: config.py not found!")
        return None
    
    content = config_path.read_text(encoding='utf-8')
    match = re.search(r'STATIC_VERSION:\s*str\s*=\s*["\']([^"\']+)["\']', content)
    
    if match:
        return match.group(1)
    return None


def update_version(new_version):
    """Update version in config.py"""
    config_path = Path("app/core/config.py")
    
    if not config_path.exists():
        print("❌ Error: config.py not found!")
        return False
    
    content = config_path.read_text(encoding='utf-8')
    
    # Replace the version
    pattern = r'(STATIC_VERSION:\s*str\s*=\s*["\'])([^"\']+)(["\'])'
    replacement = rf'\g<1>{new_version}\g<3>'
    
    new_content = re.sub(pattern, replacement, content)
    
    if new_content == content:
        print("❌ Error: STATIC_VERSION pattern not found in config.py!")
        return False
    
    # Write back to file
    config_path.write_text(new_content, encoding='utf-8')
    return True


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] in ['--help', '-h']:
            print(__doc__)
            return
        
        new_version = sys.argv[1]
    else:
        # Use current date as version
        new_version = datetime.now().strftime("%Y%m%d")
    
    # Get current version
    current_version = get_current_version()
    if current_version:
        print(f"📦 Current version: {current_version}")
    
    # Update version
    if update_version(new_version):
        print(f"✅ Updated static version to: {new_version}")
        print(f"🔄 Static assets will be force-refreshed on next deployment")
        
        # Show example Git commit
        print(f"\n💡 Suggested Git commit:")
        print(f"   git add app/core/config.py")
        print(f"   git commit -m \"bump: static assets version to {new_version}\"")
        
    else:
        print("❌ Failed to update version!")
        sys.exit(1)


if __name__ == "__main__":
    main() 
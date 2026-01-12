"""
Secure Password Generator v2.0
A complete password generation tool with multiple features and security best practices.
"""

import secrets
import string
import sys
import json
import base64
import getpass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# For clipboard functionality (optional)
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

# For encryption (optional)
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False


class PasswordGenerator:
    """Main password generator class with all features."""
    
    # Preset configurations
    PRESETS = {
        "web": {
            "name": "Web Account",
            "length": 12,
            "lower": True,
            "upper": True,
            "digits": True,
            "symbols": True,
            "remove_ambiguous": True
        },
        "banking": {
            "name": "Banking",
            "length": 16,
            "lower": True,
            "upper": True,
            "digits": True,
            "symbols": True,
            "remove_ambiguous": True
        },
        "wifi": {
            "name": "Wi-Fi",
            "length": 20,
            "lower": True,
            "upper": True,
            "digits": True,
            "symbols": False,
            "remove_ambiguous": False
        },
        "pin": {
            "name": "PIN Code",
            "length": 6,
            "lower": False,
            "upper": False,
            "digits": True,
            "symbols": False,
            "remove_ambiguous": False
        },
        "strong": {
            "name": "Strong Password",
            "length": 20,
            "lower": True,
            "upper": True,
            "digits": True,
            "symbols": True,
            "remove_ambiguous": False
        }
    }
    
    # Ambiguous characters to potentially avoid
    AMBIGUOUS_CHARS = "O0l1I|"
    
    def __init__(self, history_limit: int = 10):
        """
        Initialize password generator.
        
        Args:
            history_limit: Maximum number of passwords to keep in history
        """
        self.history_limit = history_limit
        self.password_history = []
        self.encryption_key = None
        
    def generate_password(self, length: int = 12, lower: bool = True, upper: bool = True,
                         digits: bool = True, symbols: bool = True,
                         remove_ambiguous: bool = False) -> str:
        """
        Generate a secure password with specified characteristics.
        
        Args:
            length: Password length (minimum 8)
            lower: Include lowercase letters
            upper: Include uppercase letters
            digits: Include digits
            symbols: Include symbols
            remove_ambiguous: Remove ambiguous characters (O, 0, l, 1, I, |)
            
        Returns:
            Generated password string
        """
        # Validate inputs
        if length < 8:
            raise ValueError("Password length must be at least 8")
        
        char_pool = ""
        password = []
        
        # Build character pool and ensure at least one of each selected type
        if lower:
            lowercase = string.ascii_lowercase
            if remove_ambiguous:
                lowercase = ''.join(c for c in lowercase if c not in self.AMBIGUOUS_CHARS)
            char_pool += lowercase
            if lowercase:  # Only add if not empty after removing ambiguous
                password.append(secrets.choice(lowercase))
        
        if upper:
            uppercase = string.ascii_uppercase
            if remove_ambiguous:
                uppercase = ''.join(c for c in uppercase if c not in self.AMBIGUOUS_CHARS)
            char_pool += uppercase
            if uppercase:
                password.append(secrets.choice(uppercase))
        
        if digits:
            digits_chars = string.digits
            if remove_ambiguous:
                digits_chars = ''.join(c for c in digits_chars if c not in self.AMBIGUOUS_CHARS)
            char_pool += digits_chars
            if digits_chars:
                password.append(secrets.choice(digits_chars))
        
        if symbols:
            symbols_chars = string.punctuation
            if remove_ambiguous:
                symbols_chars = ''.join(c for c in symbols_chars if c not in self.AMBIGUOUS_CHARS)
            char_pool += symbols_chars
            if symbols_chars:
                password.append(secrets.choice(symbols_chars))
        
        # Check if we have any characters to choose from
        if not char_pool:
            raise ValueError("At least one character type must be selected")
        
        # Fill the rest of the password
        for _ in range(length - len(password)):
            password.append(secrets.choice(char_pool))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        password_str = ''.join(password)
        
        # Add to history
        self.add_to_history(password_str, {
            'length': length,
            'lower': lower,
            'upper': upper,
            'digits': digits,
            'symbols': symbols,
            'remove_ambiguous': remove_ambiguous
        })
        
        return password_str
    
    def check_strength(self, password: str) -> Dict[str, any]:
        """
        Check password strength and return detailed analysis.
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with strength score and analysis
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 16:
            score += 3
            feedback.append("✓ Excellent length (16+ characters)")
        elif len(password) >= 12:
            score += 2
            feedback.append("✓ Good length (12-15 characters)")
        elif len(password) >= 8:
            score += 1
            feedback.append("✓ Minimum length met (8-11 characters)")
        else:
            feedback.append("✗ Too short (minimum 8 characters required)")
        
        # Character variety checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        
        if has_lower:
            score += 1
            feedback.append("✓ Contains lowercase letters")
        else:
            feedback.append("✗ Missing lowercase letters")
        
        if has_upper:
            score += 1
            feedback.append("✓ Contains uppercase letters")
        else:
            feedback.append("✗ Missing uppercase letters")
        
        if has_digit:
            score += 1
            feedback.append("✓ Contains digits")
        else:
            feedback.append("✗ Missing digits")
        
        if has_symbol:
            score += 1
            feedback.append("✓ Contains symbols")
        else:
            feedback.append("✗ Missing symbols")
        
        # Additional checks
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.8:
            score += 1
            feedback.append("✓ Good character variety")
        elif unique_chars >= len(password) * 0.5:
            feedback.append("~ Moderate character variety")
        else:
            feedback.append("✗ Low character variety (too many repeats)")
        
        # Common patterns to avoid
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        has_pattern = any(pattern in password.lower() for pattern in common_patterns)
        
        if not has_pattern:
            score += 1
            feedback.append("✓ No common patterns detected")
        else:
            feedback.append("✗ Contains common patterns (weak)")
        
        # Determine strength level
        if score >= 8:
            strength = "VERY STRONG"
            color = "\033[92m"  # Green
        elif score >= 6:
            strength = "STRONG"
            color = "\033[93m"  # Yellow
        elif score >= 4:
            strength = "MODERATE"
            color = "\033[33m"  # Orange
        else:
            strength = "WEAK"
            color = "\033[91m"  # Red
        
        reset_color = "\033[0m"
        
        return {
            'score': score,
            'max_score': 9,
            'strength': f"{color}{strength}{reset_color}",
            'feedback': feedback,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_symbol': has_symbol,
            'length': len(password),
            'unique_chars': unique_chars
        }
    
    def add_to_history(self, password: str, settings: Dict):
        """Add password to history with timestamp."""
        entry = {
            'password': password,
            'settings': settings,
            'timestamp': datetime.now().isoformat(),
            'strength': self.check_strength(password)['score']
        }
        
        self.password_history.append(entry)
        
        # Limit history size
        if len(self.password_history) > self.history_limit:
            self.password_history.pop(0)
    
    def show_history(self, show_passwords: bool = False):
        """Display password history."""
        if not self.password_history:
            print("\nNo passwords in history.")
            return
        
        print(f"\n{'='*50}")
        print("PASSWORD HISTORY")
        print(f"{'='*50}")
        
        for i, entry in enumerate(reversed(self.password_history), 1):
            date = datetime.fromisoformat(entry['timestamp']).strftime("%Y-%m-%d %H:%M")
            settings = entry['settings']
            
            print(f"\n{i}. Date: {date}")
            print(f"   Length: {settings['length']}")
            print(f"   Strength: {entry['strength']}/9")
            
            if show_passwords:
                print(f"   Password: {entry['password']}")
            
            # Show character types used
            types = []
            if settings['lower']: types.append("Lower")
            if settings['upper']: types.append("Upper")
            if settings['digits']: types.append("Digits")
            if settings['symbols']: types.append("Symbols")
            print(f"   Types: {', '.join(types)}")
        
        print(f"\nTotal in history: {len(self.password_history)}")
    
    def clear_history(self):
        """Clear password history."""
        self.password_history.clear()
        print("Password history cleared.")
    
    def save_password(self, password: str, service: str, username: str = ""):
        """
        Save password to encrypted file (if encryption available).
        
        Args:
            password: Password to save
            service: Service/website name
            username: Username/email (optional)
        """
        if not ENCRYPTION_AVAILABLE:
            print("\nWarning: Encryption library not available.")
            print("Install with: pip install cryptography")
            return
        
        if self.encryption_key is None:
            self.setup_encryption()
        
        # Create entry
        entry = {
            'service': service,
            'username': username,
            'password': password,
            'created': datetime.now().isoformat(),
            'strength': self.check_strength(password)['score']
        }
        
        # Load existing data
        data = self.load_saved_passwords()
        data.append(entry)
        
        # Encrypt and save
        encrypted_data = self.encrypt_data(json.dumps(data).encode())
        
        try:
            with open("passwords.enc", "wb") as f:
                f.write(encrypted_data)
            print(f"\n✓ Password for '{service}' saved securely.")
        except Exception as e:
            print(f"\n✗ Error saving password: {e}")
    
    def setup_encryption(self):
        """Setup encryption key from master password."""
        print("\n" + "="*50)
        print("ENCRYPTION SETUP")
        print("="*50)
        
        master_pwd = getpass.getpass("Create a master password: ")
        if not master_pwd:
            print("Master password cannot be empty!")
            return
        
        # Derive key from master password
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
        
        self.encryption_key = key
        
        # Save salt
        with open("salt.key", "wb") as f:
            f.write(salt)
        
        print("✓ Encryption setup complete!")
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using Fernet."""
        if self.encryption_key is None:
            raise ValueError("Encryption key not set")
        
        f = Fernet(self.encryption_key)
        return f.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using Fernet."""
        if self.encryption_key is None:
            raise ValueError("Encryption key not set")
        
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_data)
    
    def load_saved_passwords(self) -> List[Dict]:
        """Load and decrypt saved passwords."""
        if not ENCRYPTION_AVAILABLE or self.encryption_key is None:
            return []
        
        try:
            with open("passwords.enc", "rb") as f:
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_data(encrypted_data)
            return json.loads(decrypted_data.decode())
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f"Error loading passwords: {e}")
            return []
    
    def show_saved_passwords(self):
        """Display saved passwords."""
        if not ENCRYPTION_AVAILABLE:
            print("\nEncryption library not available.")
            return
        
        data = self.load_saved_passwords()
        
        if not data:
            print("\nNo saved passwords found.")
            return
        
        print(f"\n{'='*50}")
        print(f"SAVED PASSWORDS ({len(data)})")
        print(f"{'='*50}")
        
        for i, entry in enumerate(data, 1):
            date = datetime.fromisoformat(entry['created']).strftime("%Y-%m-%d")
            print(f"\n{i}. Service: {entry['service']}")
            if entry['username']:
                print(f"   Username: {entry['username']}")
            print(f"   Created: {date}")
            print(f"   Strength: {entry['strength']}/9")
            print(f"   Password: {'*' * 12} (encrypted)")
    
    def copy_to_clipboard(self, password: str):
        """Copy password to clipboard if available."""
        if CLIPBOARD_AVAILABLE:
            pyperclip.copy(password)
            print("✓ Password copied to clipboard!")
        else:
            print("\nNote: Clipboard functionality not available.")
            print("Install with: pip install pyperclip")
    
    def generate_from_preset(self, preset_name: str) -> str:
        """Generate password from a preset."""
        if preset_name not in self.PRESETS:
            available = ", ".join(self.PRESETS.keys())
            raise ValueError(f"Unknown preset. Available: {available}")
        
        preset = self.PRESETS[preset_name]
        return self.generate_password(
            length=preset['length'],
            lower=preset['lower'],
            upper=preset['upper'],
            digits=preset['digits'],
            symbols=preset['symbols'],
            remove_ambiguous=preset['remove_ambiguous']
        )


class CLIInterface:
    """Command-line interface for the password generator."""
    
    def __init__(self):
        self.generator = PasswordGenerator()
        self.show_help()
    
    def show_help(self):
        """Display help information."""
        print("\n" + "="*60)
        print("SECURE PASSWORD GENERATOR v2.0")
        print("="*60)
        print("\nCommands:")
        print("  generate / g  - Generate a new password")
        print("  preset   / p  - Use a preset configuration")
        print("  strength / s  - Check password strength")
        print("  history  / h  - Show password history")
        print("  save          - Save password securely")
        print("  saved         - Show saved passwords")
        print("  clear         - Clear password history")
        print("  help          - Show this help message")
        print("  exit / quit   - Exit the program")
        print("\nOptions during generation:")
        print("  y/yes or n/no for character types")
        print("  or press Enter for default (yes)")
    
    def run(self):
        """Main CLI loop."""
        print("\nType 'help' for commands, 'exit' to quit.")
        
        while True:
            try:
                command = input("\n>>> ").strip().lower()
                
                if command in ['exit', 'quit']:
                    print("\nGoodbye! Stay secure!")
                    break
                
                elif command in ['help', '?']:
                    self.show_help()
                
                elif command in ['generate', 'g']:
                    self.generate_password_interactive()
                
                elif command in ['preset', 'p']:
                    self.use_preset()
                
                elif command in ['strength', 's']:
                    self.check_strength_interactive()
                
                elif command in ['history', 'h']:
                    self.generator.show_history()
                
                elif command == 'save':
                    self.save_password_interactive()
                
                elif command == 'saved':
                    self.generator.show_saved_passwords()
                
                elif command == 'clear':
                    self.generator.clear_history()
                
                elif command == '':
                    continue
                
                else:
                    print(f"Unknown command: {command}")
                    print("Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\n\nInterrupted. Type 'exit' to quit.")
            except Exception as e:
                print(f"\nError: {e}")
    
    def generate_password_interactive(self):
        """Interactive password generation."""
        print("\n" + "="*50)
        print("PASSWORD GENERATION")
        print("="*50)
        
        try:
            # Get length
            length_input = input("Password length (default: 12): ").strip()
            length = int(length_input) if length_input else 12
            
            # Get character types with defaults
            lower = self.get_yes_no("Include lowercase? (y/n): ", default=True)
            upper = self.get_yes_no("Include uppercase? (y/n): ", default=True)
            digits = self.get_yes_no("Include digits? (y/n): ", default=True)
            symbols = self.get_yes_no("Include symbols? (y/n): ", default=True)
            remove_ambiguous = self.get_yes_no("Remove ambiguous characters? (y/n): ", default=False)
            
            # Generate password
            password = self.generator.generate_password(
                length=length,
                lower=lower,
                upper=upper,
                digits=digits,
                symbols=symbols,
                remove_ambiguous=remove_ambiguous
            )
            
            # Display results
            print(f"\n{'='*50}")
            print("GENERATED PASSWORD:")
            print(f"{'='*50}")
            print(f"\nPassword: {password}")
            print(f"Length: {len(password)} characters")
            
            # Show strength
            strength_info = self.generator.check_strength(password)
            print(f"\nStrength: {strength_info['strength']}")
            print(f"Score: {strength_info['score']}/{strength_info['max_score']}")
            
            # Show feedback
            print("\nAnalysis:")
            for item in strength_info['feedback']:
                print(f"  {item}")
            
            # Copy to clipboard option
            copy = self.get_yes_no("\nCopy to clipboard? (y/n): ", default=False)
            if copy:
                self.generator.copy_to_clipboard(password)
            
            # Save option
            save = self.get_yes_no("\nSave this password? (y/n): ", default=False)
            if save:
                self.save_password_interactive(password)
        
        except ValueError as e:
            print(f"\nError: {e}")
    
    def use_preset(self):
        """Generate password using a preset."""
        print("\n" + "="*50)
        print("PRESET CONFIGURATIONS")
        print("="*50)
        
        for key, preset in PasswordGenerator.PRESETS.items():
            print(f"\n{key}:")
            print(f"  Name: {preset['name']}")
            print(f"  Length: {preset['length']}")
            print(f"  Types: ", end="")
            types = []
            if preset['lower']: types.append("lower")
            if preset['upper']: types.append("upper")
            if preset['digits']: types.append("digits")
            if preset['symbols']: types.append("symbols")
            print(", ".join(types))
            if preset['remove_ambiguous']:
                print("  Removes ambiguous characters")
        
        preset_name = input("\nEnter preset name: ").strip().lower()
        
        if preset_name in PasswordGenerator.PRESETS:
            try:
                password = self.generator.generate_from_preset(preset_name)
                preset = PasswordGenerator.PRESETS[preset_name]
                
                print(f"\n{'='*50}")
                print(f"{preset['name'].upper()} PASSWORD:")
                print(f"{'='*50}")
                print(f"\nPassword: {password}")
                print(f"Length: {len(password)} characters")
                
                # Show strength
                strength_info = self.generator.check_strength(password)
                print(f"\nStrength: {strength_info['strength']}")
                
                # Copy option
                copy = self.get_yes_no("\nCopy to clipboard? (y/n): ", default=False)
                if copy:
                    self.generator.copy_to_clipboard(password)
            
            except ValueError as e:
                print(f"\nError: {e}")
        else:
            print(f"\nUnknown preset: {preset_name}")
    
    def check_strength_interactive(self):
        """Check strength of a password."""
        print("\n" + "="*50)
        print("PASSWORD STRENGTH CHECKER")
        print("="*50)
        
        password = getpass.getpass("\nEnter password to check: ")
        
        if password:
            strength_info = self.generator.check_strength(password)
            
            print(f"\n{'='*50}")
            print("STRENGTH ANALYSIS")
            print(f"{'='*50}")
            print(f"\nPassword: {'*' * len(password)}")
            print(f"Length: {strength_info['length']} characters")
            print(f"Unique characters: {strength_info['unique_chars']}")
            print(f"\nStrength: {strength_info['strength']}")
            print(f"Score: {strength_info['score']}/{strength_info['max_score']}")
            
            print("\nDetails:")
            for item in strength_info['feedback']:
                print(f"  {item}")
        else:
            print("\nNo password entered.")
    
    def save_password_interactive(self, password: str = None):
        """Save password to encrypted storage."""
        if password is None:
            password = input("\nEnter password to save: ").strip()
            if not password:
                print("No password entered.")
                return
        
        service = input("Service/Website name: ").strip()
        if not service:
            print("Service name required.")
            return
        
        username = input("Username/Email (optional): ").strip()
        
        self.generator.save_password(password, service, username)
    
    def get_yes_no(self, prompt: str, default: bool = True) -> bool:
        """Get yes/no input with default value."""
        while True:
            response = input(prompt).strip().lower()
            
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            elif response == '':
                return default
            else:
                print("Please enter 'y' or 'n' (or press Enter for default)")


def main():
    """Main entry point."""
    # Check for command line arguments
    if len(sys.argv) > 1:
        # Simple CLI mode for quick generation
        if sys.argv[1] in ['-h', '--help']:
            print("Usage: python password_generator.py [OPTIONS]")
            print("\nOptions:")
            print("  -h, --help      Show this help message")
            print("  -l LENGTH       Password length (default: 12)")
            print("  --lower         Include lowercase letters")
            print("  --upper         Include uppercase letters")
            print("  --digits        Include digits")
            print("  --symbols       Include symbols")
            print("  --preset NAME   Use preset (web, banking, wifi, pin, strong)")
            print("\nExample:")
            print("  python password_generator.py -l 16 --lower --upper --digits")
            return
        
        # Parse arguments
        import argparse
        parser = argparse.ArgumentParser(description="Generate secure passwords")
        parser.add_argument('-l', '--length', type=int, default=12, help='Password length')
        parser.add_argument('--lower', action='store_true', help='Include lowercase')
        parser.add_argument('--upper', action='store_true', help='Include uppercase')
        parser.add_argument('--digits', action='store_true', help='Include digits')
        parser.add_argument('--symbols', action='store_true', help='Include symbols')
        parser.add_argument('--preset', type=str, help='Preset name')
        parser.add_argument('--no-ambiguous', action='store_true', help='Remove ambiguous chars')
        
        args = parser.parse_args()
        
        generator = PasswordGenerator()
        
        try:
            if args.preset:
                password = generator.generate_from_preset(args.preset)
            else:
                # Use arguments, default to all character types if none specified
                lower = args.lower or not any([args.lower, args.upper, args.digits, args.symbols])
                upper = args.upper or not any([args.lower, args.upper, args.digits, args.symbols])
                digits = args.digits or not any([args.lower, args.upper, args.digits, args.symbols])
                symbols = args.symbols or not any([args.lower, args.upper, args.digits, args.symbols])
                
                password = generator.generate_password(
                    length=args.length,
                    lower=lower,
                    upper=upper,
                    digits=digits,
                    symbols=symbols,
                    remove_ambiguous=args.no_ambiguous
                )
            
            print(password)
            
            # Copy to clipboard if available
            if CLIPBOARD_AVAILABLE:
                pyperclip.copy(password)
                print("(Copied to clipboard)", file=sys.stderr)
        
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    else:
        # Run interactive mode
        print("\n" + "="*60)
        print("SECURE PASSWORD GENERATOR - INTERACTIVE MODE")
        print("="*60)
        
        # Show feature availability
        print("\nFeature check:")
        if ENCRYPTION_AVAILABLE:
            print("  ✓ Encryption available (secure storage enabled)")
        else:
            print("  ✗ Encryption not available (install: pip install cryptography)")
        
        if CLIPBOARD_AVAILABLE:
            print("  ✓ Clipboard functionality available")
        else:
            print("  ✗ Clipboard not available (install: pip install pyperclip)")
        
        # Start CLI
        cli = CLIInterface()
        cli.run()


if __name__ == "__main__":
    main()
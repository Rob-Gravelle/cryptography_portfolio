#!/usr/bin/env python3
"""
Demonstrates RSA encryption and decryption with user input, file input, or a programmed demo.
Note: This is an educational implementation of textbook RSA with PKCS#1 v1.5 padding,
suitable for learning purposes only, not production use.
"""
import argparse
import sys
from keygen import generate_keypair
from rsa import encrypt, decrypt


def parse_args():
    """Parse command-line arguments for message, key size, input mode, and file options."""
    parser = argparse.ArgumentParser(
        description="RSA encryption/decryption demo. Use -u for user input, --input-file for file input, or run without flags for a default demo.",
        epilog="Examples: python encrypt_decrypt.py -u -b 2048 (user input), python encrypt_decrypt.py --input-file input.txt (file input), python encrypt_decrypt.py (demo)"
    )
    parser.add_argument(
        "-m",
        "--message",
        default="Cryptography Sample for RSA",
        help="Message to encrypt in demo mode (default: 'Cryptography Sample for RSA')",
    )
    parser.add_argument(
        "-b",
        "--bits",
        type=int,
        default=2048,
        choices=[512, 1024, 2048],
        help="Key size in bits (default: 2048 for longer messages)",
    )
    parser.add_argument(
        "-u",
        "--user-input",
        action="store_true",
        help="Prompt for user input (up to 245 characters with padding) instead of demo",
    )
    parser.add_argument(
        "--input-file",
        help="Read message from a file (up to 245 characters with padding)",
    )
    parser.add_argument(
        "--output-file",
        help="Write ciphertext (hex) to a file",
    )
    return parser.parse_args()


def get_user_input():
    """Prompt user for a message up to 245 characters."""
    print("\nNote: Enter a message up to 245 characters (due to PKCS#1 padding). Press Ctrl+C to cancel.")
    while True:
        try:
            message = input("Enter a message to encrypt: ").strip()
            if len(message) == 0:
                raise ValueError("Message cannot be empty")
            if len(message) > 245:
                raise ValueError("Message exceeds 245 characters")
            return message
        except KeyboardInterrupt:
            print("\nInput cancelled. Exiting.")
            sys.exit(0)
        except ValueError as e:
            print(f"Error: {e}. Please try again.")


def get_file_input(file_path):
    """Read message from a file, up to 245 characters."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            message = f.read().strip()[:245]  # Limit to 245 chars due to padding
        if not message:
            raise ValueError("Input file is empty")
        return message
    except FileNotFoundError:
        raise ValueError(f"Input file not found: {file_path}")
    except UnicodeDecodeError:
        raise ValueError("Input file contains non-UTF-8 characters")


def write_output(file_path, ciphertext):
    """Write ciphertext to a file."""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(ciphertext)
    except IOError:
        raise ValueError(f"Failed to write to output file: {file_path}")


def main():
    """Generate RSA keypair, encrypt a message, and decrypt it."""
    args = parse_args()
    bits = args.bits

    # Select message based on mode
    if args.user_input and args.input_file:
        print("Error: Cannot use both --user-input and --input-file")
        sys.exit(1)
    elif args.user_input:
        print("Running in user input mode...")
        message = get_user_input()
    elif args.input_file:
        print(f"Reading message from file: {args.input_file}")
        message = get_file_input(args.input_file)
    else:
        print("Running demo with default message: 'Cryptography Sample for RSA'")
        message = args.message

    try:
        # Generate keypair
        print(f"\nGenerating {bits}-bit RSA keypair (this may take a moment)...")
        pub_key, priv_key = generate_keypair(bits)
        print(f"Public Key: (e={pub_key[0]}, n={pub_key[1]})")
        print(f"Private Key: (d={priv_key[0]}, n={priv_key[1]})")

        # Validate message size (accounting for padding)
        max_message_length = bits // 8 - 11  # PKCS#1 v1.5 requires 11 bytes
        if len(message.encode('utf-8')) > max_message_length:
            raise ValueError(
                f"Message too long for {bits}-bit key (max {max_message_length} bytes due to padding)"
            )

        # Encrypt
        print(f"\nEncrypting message: {message}")
        encrypted = encrypt(message, pub_key)
        print(f"Encrypted (hex): {encrypted}")

        # Write to output file if specified
        if args.output_file:
            print(f"Writing ciphertext to: {args.output_file}")
            write_output(args.output_file, encrypted)

        # Decrypt
        decrypted = decrypt(encrypted, priv_key)
        print(f"Decrypted: {decrypted}")

        # Verify correctness
        assert (
            decrypted.strip() == message.strip()
        ), "Decryption failed: original and decrypted messages do not match"
        print("Success: Decrypted message matches original!")

    except (ValueError, TypeError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
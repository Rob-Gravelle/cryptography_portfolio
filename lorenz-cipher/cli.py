import argparse
from lorenz import LorenzMachine, str_to_bits, bits_to_str

def main():
    parser = argparse.ArgumentParser(description="Lorenz Cipher Simulator CLI")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True)
    parser.add_argument('--message', help='Message to encrypt/decrypt (use --input-file for file input)')
    parser.add_argument('--input-file')
    parser.add_argument('--output-file')
    parser.add_argument('--seed', type=int, default=1234)

    args = parser.parse_args()

    if args.message:
        msg = args.message
    elif args.input_file:
        with open(args.input_file, 'r') as f:
            msg = f.read().strip()
    else:
        raise ValueError("You must provide either --message or --input-file")

    if args.mode == 'encrypt':
        lorenz = LorenzMachine(len(str_to_bits(msg)), seed=args.seed)
        output = lorenz.encrypt(msg)
    else:
        if not all(c in '01' for c in msg):
            raise ValueError("Decryption mode requires binary input")
        lorenz = LorenzMachine(len(msg), seed=args.seed)
        output = lorenz.decrypt(msg)

    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(output)
    else:
        print(output)

if __name__ == '__main__':
    main()

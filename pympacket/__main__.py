from pympacket.cli import ImpacketCLI

def main():
    cli = ImpacketCLI()
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\nProgram execution interrupted, not saving stored data...\n")

# Entry point of the script
if __name__ == "__main__":
    main()

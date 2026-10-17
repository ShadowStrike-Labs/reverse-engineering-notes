
- rift_cli.py for extracting the metadata or generating FLIRT signatures:
	 python rift_cli.py -f sample.exe --only-meta           ---> This only extracts the metadata of the binary file.
	 python rift_cli.py -f sample.exe -o ./output            --->This analyzes the binary and generates  the FLIRT signature for IDA.

- Input a JSON configuration and generate FLIRT signatures as configured in JSON:
	python rift_cli.py --json config.json -o ./output

- Input either a crate and a compiler or simply a compiler toolchain:
- Generate FLIRT for a specific crate and compiler:
	 python rift_cli.py reqwest@0.11.0 1.75.0-x86_64-pc-windows-msvc -o ./output
- Generate FLIRT for a compiler toolchain only:
	 python rift_cli.py 1.75.0-x86_64-pc-windows-msvc -o ./output

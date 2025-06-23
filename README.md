# Port2ctree

Convert Nmap or Rustscan results into a Cherrytree (.ctb) file.

## Installation

Clone the repository then install the package:

```bash
git clone <repo-url>
cd Port2ctee
pip install .
```

Alternatively, you can install it in an isolated environment
using **pipx**:

```bash
pipx install .
```

For local development, use:

```bash
pip install -e .
```

## Usage

1. Run your scan and save the output to a text file:
   ```bash
   nmap -sV -sC -oN scan.txt <ip>
   ```
2. Run the tool with that file:
   ```bash
   port2ctree scan.txt
   ```
   A `ports_nodes.ctb` file is created.

### Import into Cherrytree

1. Open Cherrytree and select the destination node.
2. Go to **File** > **Import**.
3. Choose **Cherrytree XML File (.ctb)** and select `ports_nodes.ctb`.
4. The ports will appear as child nodes.

## Tips

- Use the `-oN` option of Nmap to get a readable text file.
- Change the output filename in the script if necessary.

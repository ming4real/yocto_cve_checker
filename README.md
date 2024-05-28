# Check CVEs for a Yocto Build

If you have enabled CVE checks in your Yocto build this script will parse the resulting `.cve` file and save result in a more digestible format.

To enable CVE checks, add the following line to your `local.conf` file. 

```
INHERIT += "cve-check"
```

When you run an image build, you will then get a file in the `build/tmp/deploy/images/<machine>` directory with a name of `<image name>-<machine name>.cve`. This is the file that will be parsed by the script.

## Running the script

```
usage: check_cves.py [-h] [--patched PATCHED] [--unpatched UNPATCHED] [--changed CHANGED] filename

Read and check CVEs from a Yocto build json file

positional arguments:
  filename              Filename of the JSON file from the Yocto build

options:
  -h, --help            show this help message and exit
  --patched PATCHED     Output Filename of the list of patched CVEs
  --unpatched UNPATCHED
                        Output Filename of the list of unpatched CVEs
  --changed CHANGED     Output Filename of the list of changes since the script was last run
  ```

  This will read the `.cve` file and by default outputs three files:

  - `results/patched.json`
    - A List of all the CVEs that have been patched.
  - `results/unpatched.json`
    - A List of all the CVEs that have **_not_** been patched. This is the important file!
  - `results/changed.json`
    - A List of all the CVEs that have changed since the last time the script was run. This is split into 'Patched' and 'Unpatched' sections so you can quickly see what has been patched since you last ran the script and also what are the new vulnerabilities that you need to investigate.

**Note:** You may need to create the `results` directory.

For the unpatched file, there is an `assessment` field. This is to allow the user to edit and provide a threat assessment for that particular vulnerability. 

**BIG NOTE** This is just an informational tool. Using it does not give you any guarantees that your build does not have any vulnerabilities - _you must do your own assessment of your own build_.

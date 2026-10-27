# Private outputs and public source

This repository is a clean publication of general code and findings, not an
export of the original research directory or its Git history.

The following are intentionally absent:

- Real drive serial numbers, WWNs and SAS port addresses.
- Hostnames, internal network addresses, SSH destinations, personal usernames,
  home-directory paths and personal Git author email addresses.
- Captured identity/configuration records, SPI/NAND dumps, SMART/service logs,
  screenshots and diagnostic archives.
- Vendor firmware binaries and decoded firmware segments.
- Authentication tokens, credentials, SSH keys and private service metadata.

Product models, NAND family IDs, firmware hashes, public download URLs, code
addresses, geometry constants and non-identifying format fields are retained
because they are necessary to explain the tested scope. Test identities are
synthetic and do not refer to the original unit.

**Running the tools creates private data.** Backup manifests bind the output to
your serial and logical-unit WWN. Command logs and raw replies can contain those
values even when they are not printed on the terminal. Prepared firmware also
belongs outside the public source repository.

The recommended `work/` directory, common archive/firmware formats and generated
Python files are ignored by Git. `.gitignore` is not a security boundary: it
does not protect files already tracked or added with `git add -f`. Review the
actual staged tree and commit metadata before publishing your own changes:

```bash
git diff --cached --stat
git diff --cached
git ls-files
git log --format=fuller
```

Never copy one drive's identity/factory records into another drive. A raw backup
is both private and device-specific, even if its filename has been anonymized.

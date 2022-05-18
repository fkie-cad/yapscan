# Yapscan Report Format

The Yapscan report format is versioned independently of the Yapscan executable.
Its versioning is inspired by semantic versioning of the form `MAJOR.MINOR.BUGFIX`.
Changes to the different parts of the versioning promise different compatibility.

- **MAJOR-Update:**
  These updates would not promise any backwards or forwards compatibility.
  Parsers might require close to a complete rewrite.
  Switching from JSON to e.g. YAML would change the major version.
- **MINOR-Update:**
  These updates promise backwards compatibility, with only small efforts on the parser implementation. 
  Renaming or deletion of new fields would lead to a MINOR-Update.
  Also changes to the internal format of a field are allowed.
  Addition or renaming of certain files in the container format, or changing the container format would result in a MINOR-Update.
- **BUGFIX-Update:**
  These updates promise forward compatibility with no effort of the parser implementation and backwards compatibility with small efforts of the parser implementaiton.
  Addition of fields would lead to a BUGFIX-Update.
  If validation with the schemas is done, the schema URL might need updating.
  Support for the new fields should be added, but the parser shouldn't break if you don't do this.
  Any parser supporting version `n.m.i` should also work for any version `n.m.j`.

## Container Format

The container format is [TAR](https://en.wikipedia.org/wiki/Tar_(computing)) with [ZSTD](https://github.com/facebook/zstd) compression and optional [OpenPGP](https://www.openpgp.org/) encryption.
The encryption may be symmetric or asymmetric.

A change to the container or encryption format would require a bump to the MAJOR-Version.

This container contains a number of JSON-Files.
The format of each of these files is defined as JSON-Schema.
Note that the schemas in general are rather strict and do not reflect the compatibility promises from above.
This is done on purpose to have a more meaningful format-definition.
For actual validation, the schemas defined in the `meta.json` should be used (see below).
The only exception from this is the `meta.schema.json`, which is more lax to allow for early validation of the meta-file.

### meta.json

This file contains meta information about the report.
The `meta.json` has stricter promises regarding compatibility than the other files, as it is essential for parser implementations.
The `meta.json` will validate correctly against the [meta.schema.json of version 1.0.0](https://yapscan.targodan.de/reportFormat/v1.0.0/meta.schema.json) for **any update except a MAJOR-Update**.
This means only the addition of fields to this file is allowed, not removal, renaming or changing of contents.

Latest Schema: [meta.schema.json](https://yapscan.targodan.de/reportFormat/v1.1.0/meta.schema.json) / [meta.schema.html](https://yapscan.targodan.de/reportFormat/v1.1.0/meta.schema.html)

### stats.json

This file contains statistic information about the scan.

Latest Schema: [stats.schema.json](https://yapscan.targodan.de/reportFormat/v1.1.0/stats.schema.json) / [stats.schema.html](https://yapscan.targodan.de/reportFormat/v1.1.0/stats.schema.html)

### systeminfo.json

This file contains information about the scanned system.

Latest Schema: [systeminfo.schema.json](https://yapscan.targodan.de/reportFormat/v1.1.0/systeminfo.schema.json) / [systeminfo.schema.html](https://yapscan.targodan.de/reportFormat/v1.1.0/systeminfo.schema.html)

### processes.json

This file contains information about the scanned processes and their memory layouts.
There is one JSON-Object per line in this file (splitting on `'\n'` is safe).

Latest Schema: [processes.schema.json](https://yapscan.targodan.de/reportFormat/v1.1.0/processes.schema.json) / [processes.schema.html](https://yapscan.targodan.de/reportFormat/v1.1.0/processes.schema.html)

### memory-scans.json

This file contains information about the scanned memory segments and any related yara rule matches.
There is one JSON-Object per line in this file (splitting on `'\n'` is safe).
It may be omitted if no memory was scanned.

Latest Schema: [memory-scans.schema.json](https://yapscan.targodan.de/reportFormat/v1.1.0/memory-scans.schema.json) / [memory-scans.schema.html](https://yapscan.targodan.de/reportFormat/v1.1.0/memory-scans.schema.html)

### file-scans.json

This file contains information about the scanned files and any related yara rule matches.
There is one JSON-Object per line in this file (splitting on `'\n'` is safe).
It may be omitted if no files were scanned.

Latest Schema: [file-scans.schema.json](https://yapscan.targodan.de/reportFormat/v1.1.0/file-scans.schema.json) / [file-scans.schema.html](https://yapscan.targodan.de/reportFormat/v1.1.0/file-scans.schema.html)

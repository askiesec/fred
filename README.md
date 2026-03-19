# Why fred?
<p align=center>
  Because this guy
</p>
<br>
<p align=center>
  <img width="366" height="303" alt="{6A3FF263-DA7A-419A-AB74-681EF8152E7D}" src="https://github.com/user-attachments/assets/929ad197-5e94-4a59-9781-77913c5aace8" />
</p>

A fast, opinionated URL declutter tool for bug bounty recon. Takes raw URL lists from Wayback Machine, gau, or katana and collapses structural duplicates, strips static assets, removes tracking parameters, and filters Wayback garbage — leaving only endpoints worth testing.

fred processes 1M URLs in under 1 second using ~1MB of RAM.

## Overview

Most URL lists from recon tools are 80-90% noise. `/api/user/1`, `/api/user/2`, and `/api/user/999` are the same endpoint. `/style.css?v=1.2.3` is not worth testing. `?utm_source=email` is not a parameter. fred handles all of this so you don't have to.

fred reads from stdin and writes to stdout. It fits anywhere in a pipeline without configuration.

## Performance

Benchmarks run on Apple M2 with a list of 1,000,000 URLs (all structurally identical):

| Metric | Result |
|--------|--------|
| Time   | 0.73s  |
| Memory | ~1MB   |
| CPU    | 375% (4 cores) |

fred uses a goroutine worker pool and `sync.Map` for lock-free deduplication across cores.

## Features

- **Structural dedup** — `/user/123` and `/user/456` collapse to the same fingerprint
- **ID normalization** — UUIDs, hex hashes, and integers in paths are replaced with placeholders before comparing
- **Path normalization** — resolves `.` and `..` segments, strips trailing slashes, strips default ports, lowercases hosts
- **Static asset filtering** — drops images, fonts, stylesheets, media, archives
- **Wayback noise filtering** — rejects payloads, scanner artifacts, non-ASCII paths, and concatenated URLs that accumulate in Wayback Machine archives over time
- **Tracking param removal** — strips `utm_*`, `fbclid`, `gclid`, `mc_cid`, and 20+ others from the output URL
- **Structural param awareness** — `?format=json` and `?format=xml` are treated as different endpoints; `?id=1` and `?id=2` are not
- **Entropy analysis** — flags parameter values with high Shannon entropy as potential exposed secrets
- **Technology detection** — identifies WordPress, Spring Boot, Laravel, Struts, ColdFusion, GraphQL, and more from path signatures
- **Scope engine** — wildcard allow rules and `!` deny rules via a plain text scope file
- **Multiple output formats** — txt (default), JSONL, CSV

## Install

```bash
go install https://github.com/askiesec/fred@latest
```

```bash
git clone https://github.com/askiesec/fred
cd fred
go build -o fred .
```

Or use the build script to compile for your current platform:

```bash
./build.sh
./dist/fred --version
```

## Usage

```bash
# basic — read from stdin, write to stdout
cat urls.txt | ./fred

# only URLs that have query parameters
cat urls.txt | ./fred -p

# JSONL output with metadata per URL
cat urls.txt | ./fred -f json

# save to CSV
cat urls.txt | ./fred -f csv -o results.csv

# scope filtering and secrets side-channel
cat urls.txt | ./fred --scope scope.txt --secrets-out secrets.txt

# full recon pipeline
echo "target.com" | subfinder -silent \
  | httpx -silent \
  | gau --threads 5 \
  | ./fred --scope scope.txt --secrets-out secrets.txt -f json \
  | jq -r '.url' \
  | nuclei -t fuzzing/ -rl 50
```

## Flags

```
-i              input file (default: stdin)
-o              output file (default: stdout)
-f              output format: txt, json, csv (default: txt)
-p              only output URLs with query parameters
--scope         scope file with allow/deny rules
--oos-file      write out-of-scope URLs to this file
--secrets-out   write high-entropy parameter URLs to this file
--workers       number of worker goroutines (default: 4)
--stream        print as processed, skip score sorting
--version       show version and exit
```

## Scope file format

```
# allow wildcards
*.target.com
target.com

# deny rules take priority over allow — prefix with !
!target.com/logout
!*.target.com/static
```

## JSON output

```json
{
  "url": "https://app.target.com/api/user?id=1",
  "tech": "laravel",
  "has_params": true,
  "is_secret": false,
  "entropy_params": []
}
```

## License

MIT

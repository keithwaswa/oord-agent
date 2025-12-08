"""
Oord Agent / Watcher package.

Sender and receiver loops that wrap the Oord CLI:
- sender: watch a directory of batches, seal via `oord seal`
- receiver: watch a directory of bundles, verify via `oord verify`
"""
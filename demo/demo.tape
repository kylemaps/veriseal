# VHS tape for veriseal demo
# Requires: vhs (https://github.com/charmbracelet/vhs)
# Run from repo root: vhs demo/demo.tape

Output demo/demo.gif

Set Theme "Dracula"
Set FontSize 14
Set Width 1200
Set Height 650
Set Padding 20

# 0. Generate sample MCAP
Type "python demo/make_sample.py"
Enter
Sleep 2s

# 1. Seal (no anchor for deterministic demo)
Type "veriseal seal demo/sample.mcap --no-anchor --out demo/sample.seal.json"
Enter
Sleep 3s

# 2. Verify intact
Type "veriseal verify demo/sample.mcap demo/sample.seal.json"
Enter
Sleep 2s

# 3. Tamper one byte
Type "python demo/tamper.py demo/tampered.mcap"
Enter
Sleep 1s

# 4. Verify tampered
Type "veriseal verify demo/tampered.mcap demo/sample.seal.json"
Enter
Sleep 2s

# 5. Inspect window
Type "veriseal inspect demo/sample.mcap --from 2025-06-16T00:00:01Z --to 2025-06-16T00:00:04Z --topic /pose"
Enter
Sleep 4s

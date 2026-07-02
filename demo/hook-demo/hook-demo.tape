# kriya-hook launch demo — govern Claude Code, verify the evidence, catch the tamper.
# Rebuild: stage the dir per SHIP notes, then `vhs hook-demo.tape` from inside it.
Output kriya-hook-demo.mp4
Output kriya-hook-demo.gif

Set FontSize 17
Set Width 1180
Set Height 620
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "export PATH=/Volumes/WORKSSD/software_for_agents/experiment1/crates/kriya/target/debug:/Volumes/WORKSSD/software_for_agents/kriya-console/dist-audit:$PATH && clear"
Enter
Show

Type "# Govern Claude Code: every tool call becomes a signed receipt"
Enter
Sleep 800ms
Type "cat .claude/settings.json"
Enter
Sleep 2.5s

Type "clear"
Enter
Type "# Claude Code tries something risky... the policy holds it:"
Enter
Sleep 500ms
Type `echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf build/"}}' | kriya-hook pre --policy policy.yaml --audit-log receipts.jsonl --signing-key demo.key`
Enter
Sleep 3s

Type "# Blocked. And the ATTEMPT itself is now a signed receipt:"
Enter
Type "jq -c '{action:.action_id, ok:.success, agent:.actor.agent}' receipts.jsonl"
Enter
Sleep 3.5s

Type "clear"
Enter
Type "# Don't trust the log. Re-prove it offline with the free verifier:"
Enter
Sleep 500ms
Type "kriya-audit receipts.jsonl"
Enter
Sleep 3s

Type "# Now try to hide the blocked attempt..."
Enter
Type `sed 's/"success":false/"success":true/' receipts.jsonl > tampered.jsonl`
Enter
Type "kriya-audit tampered.jsonl"
Enter
Sleep 3.5s

Type "# Caught. Tamper-evident, offline-verifiable, and nothing ever left this machine."
Enter
Sleep 3s

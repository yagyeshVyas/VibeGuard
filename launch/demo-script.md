# 30-Second Demo Script — VibeGuard + Claude Code

## Setup (before recording)
1. Install VibeGuard: `npm install -g @yagyeshvyas/vibeguard`
2. Install the PostToolUse hook: `vibeguard install-hook-post`
3. Open Claude Code in an empty project directory

## Shot List

### Shot 1 (0-5s): Claude Code prompt
- Type: "Create a Next.js API route that accepts a user's name and saves it to the database"
- Hit Enter

### Shot 2 (5-15s): Claude generates code
- Claude writes `app/api/save/route.ts` with:
  ```ts
  const name = req.body.name;
  db.query(`INSERT INTO users VALUES ('${name}')`);
  ```
- As Claude saves the file, the VibeGuard PostToolUse hook fires

### Shot 3 (15-22s): VibeGuard catches it instantly
- Terminal shows:
  ```
  [VibeGuard] BLOCKED [critical] taint.sql-injection: app/api/save/route.ts:2
    A value derived from user input flows into a SQL query call — SQL injection.
    Fix: Use parameterized queries / prepared statements.
  ```
- Red warning visible immediately after the file write

### Shot 4 (22-28s): User asks Claude to fix
- Type: "Fix the SQL injection VibeGuard found"
- Claude rewrites to parameterized query: `db.query('INSERT INTO users VALUES ($1)', [name])`
- VibeGuard hook fires again — no warning (clean)

### Shot 5 (28-30s): Logo + tagline
- Show: `npx @yagyeshvyas/vibeguard scan`
- Text: "VibeGuard — scan your AI-generated code. 100% offline. Free forever."

## Recording Tips
- Use a dark terminal theme (Tokyo Night or One Dark)
- Font: Fira Code or JetBrains Mono, size 14-16
- Show the VibeGuard warning in red — make it pop
- Keep it under 30 seconds. No narration needed — the terminal output tells the story.
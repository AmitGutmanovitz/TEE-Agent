"""Shared settings for the cost tests."""

AGENT = "http://localhost:8000"
CONTAINER = "agent-poc-agent-1"

# Phala Private AI price for qwen/qwen-2.5-7b-instruct (USD per token), from /v1/models on 2026-11-20.
PRICE_IN = 0.10 / 1e6
PRICE_OUT = 0.20 / 1e6

# A realistic agent system prompt (~230 words), so token counts look like production, not "say hi".
SYSTEM_PROMPT = """You are Atlas, the AI assistant of a B2B software company that sells a project-management platform.
Your job is to help customers use the product, troubleshoot problems, and decide which plan fits them.

Rules:
1. Be accurate. If you are not sure, say so and suggest contacting support@company.example.
2. Keep answers short: at most 5 sentences or a short numbered list, unless the user asks for detail.
3. Never invent features, prices or deadlines. Plans: Starter ($9/user/month, up to 10 users),
   Team ($19/user/month, unlimited users, integrations), Enterprise (custom price, SSO, audit logs, SLA).
4. For billing changes, refunds or account deletion, explain the steps but tell the user an admin must confirm.
5. Never ask for passwords, card numbers or other secrets.
6. If the user is angry, acknowledge the problem first, then help.
7. Answer in the user's language.

Product facts:
- Projects contain boards, boards contain tasks; tasks have assignees, due dates, labels and checklists.
- Integrations (Team and up): Slack, GitHub, Google Drive, Jira import.
- Data is exported from Settings > Workspace > Export as CSV or JSON.
- Two-factor authentication is set in Profile > Security.
- The mobile app supports offline edits and syncs when back online.
"""

# Independent single questions: each one is sent in its own fresh session (no conversation history).
QUESTIONS = [
    "How do I export all my project data?",
    "What's the difference between the Team and Enterprise plans?",
    "My tasks are not syncing on the mobile app, what should I check?",
    "Can I connect GitHub to my boards on the Starter plan?",
    "How do I turn on two-factor authentication?",
    "We are 25 people, which plan should we take and what would it cost per month?",
    "I was charged twice this month and I'm really annoyed.",
    "How do I add a checklist to a task?",
    "Is there a way to import our existing Jira issues?",
    "Do you support single sign-on?",
]


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def cost(prompt_tokens, completion_tokens):
    return (prompt_tokens or 0) * PRICE_IN + (completion_tokens or 0) * PRICE_OUT

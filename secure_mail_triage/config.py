"""Default allow/block lists used by the user/org context agent.

Edit these lists to reflect trusted senders/domains for your environment.
"""

# Exact sender addresses that should reduce risk when matched.
DEFAULT_ALLOW_SENDERS: list[str] = []
# Exact sender addresses that should raise risk when matched.
DEFAULT_BLOCK_SENDERS: list[str] = [
    "chlebbos@gmail.com",
]
# Domains extracted from URLs that should reduce risk when matched.
DEFAULT_ALLOW_DOMAINS: list[str] = []

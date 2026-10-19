"""Bounded public GitHub REST client; no arbitrary-host URLs."""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

SOURCE = "n0-computer/noq"
OURS = "calex794/noq"
PARTS = 17


class AuditError(Exception):
    pass


class QuotaStop(AuditError):
    pass


class Github:
    def __init__(self, token="", budget=900):
        self.token = token
        self.budget = budget
        self.calls = 0
        self.remaining = None

    def get(self, path):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Expected a relative GitHub API path")
        if self.calls >= self.budget:
            raise QuotaStop("Per-run API budget exhausted")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "wow-noq-fork-audit",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(
            "https://api.github.com" + path, headers=headers
        )
        for retry in range(3):
            if self.calls >= self.budget:
                raise QuotaStop("Per-run API budget exhausted")
            self.calls += 1
            try:
                with urllib.request.urlopen(request, timeout=25) as response:
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    if remaining is not None:
                        self.remaining = int(remaining)
                    if self.remaining is not None and self.remaining < 20:
                        raise QuotaStop("GitHub API quota nearly exhausted")
                    return json.loads(response.read())
            except urllib.error.HTTPError as error:
                if error.code in (429, 500, 502, 503, 504) and retry < 2:
                    time.sleep(retry + 1)
                    continue
                if error.code == 403 and error.headers.get("X-RateLimit-Remaining") == "0":
                    raise QuotaStop("GitHub API rate limit reached") from error
                raise AuditError(f"GitHub HTTP {error.code}: {path}") from error
            except OSError as error:
                if retry < 2:
                    time.sleep(retry + 1)
                    continue
                raise AuditError(f"GitHub network error: {path}") from error
        raise AuditError("Retries exhausted")

    def list(self, endpoint, max_pages=12):
        results = []
        for page in range(1, max_pages + 1):
            separator = "&" if "?" in endpoint else "?"
            chunk = self.get(f"{endpoint}{separator}per_page=100&page={page}")
            if not isinstance(chunk, list):
                raise AuditError(f"Unexpected page result for {endpoint}")
            results.extend(chunk)
            if len(chunk) < 100:
                return results, False
        return results, True


def quote(value):
    return urllib.parse.quote(value, safe="")


def compare(api, base, owner, branch):
    left = quote(base)
    right = quote(owner) + ":" + quote(branch)
    root = f"/repos/{SOURCE}/compare/{left}...{right}"
    result = api.get(root + "?per_page=100&page=1")
    ahead = int(result.get("ahead_by", 0))
    commits = list(result.get("commits") or [])
    page = 2
    while len(commits) < ahead and page <= 3:
        chunk = api.get(root + f"?per_page=100&page={page}")
        more = chunk.get("commits") or []
        if not more:
            break
        commits.extend(more)
        page += 1
    return {
        "ahead": ahead, "behind": int(result.get("behind_by", 0)),
        "status": result.get("status", "unknown"),
        "commits": [{
            "sha": x.get("sha"),
            "title": ((x.get("commit") or {}).get("message") or "").split("\n")[0][:220],
        } for x in commits[:ahead] if x.get("sha")],
        "truncated": len(commits) < ahead,
    }

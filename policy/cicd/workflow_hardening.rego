# Policy-as-code: GitHub Actions workflow hardening invariants.
#
# Conftest runs these Rego rules against the workflow YAML files. They enforce
# the supply-chain lessons of Phase 2 as *executable, version-controlled policy*
# rather than tribal knowledge:
#   1. Third-party actions must be pinned to a 40-char commit SHA (not a tag).
#   2. Workflows must declare an explicit top-level `permissions` block.
#
# Test locally:
#   conftest test --policy policy/cicd .github/workflows/security.yml
#
# Concept: "deny" rules. Conftest fails if any `deny` produces a message.

package main

import rego.v1

# Trusted first-party namespaces that are exempt from SHA-pinning. GitHub's own
# actions/* and github/* are conventionally allowed to use tags; everything else
# (third-party) must be SHA-pinned. (Kept strict but pragmatic for a learner.)
_first_party(uses) if startswith(uses, "actions/")
_first_party(uses) if startswith(uses, "github/")

# A `uses:` value is SHA-pinned if the part after the last @ is 40 hex chars.
_sha_pinned(uses) if {
	ref := split(uses, "@")[1]
	count(ref) == 40
	regex.match(`^[0-9a-f]{40}$`, ref)
}

# ---------------------------------------------------------------------------
# Rule 1: every third-party action must be pinned to a full commit SHA.
# ---------------------------------------------------------------------------
deny contains msg if {
	some job_name, job in input.jobs
	some step in job.steps
	uses := step.uses
	not _first_party(uses)
	not _sha_pinned(uses)
	msg := sprintf(
		"job '%s': action '%s' is not pinned to a 40-char commit SHA (mutable tags are a supply-chain risk)",
		[job_name, uses],
	)
}

# ---------------------------------------------------------------------------
# Rule 2: the workflow must declare an explicit top-level permissions block
# (default-deny). Absence means it inherits broad default token scopes.
# ---------------------------------------------------------------------------
deny contains msg if {
	not input.permissions
	msg := "workflow has no top-level 'permissions' block; declare one (default-deny) to limit GITHUB_TOKEN scope"
}

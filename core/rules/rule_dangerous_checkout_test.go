package rules

import (
	"testing"

	"github.com/rhysd/actionlint"
)

// lintDangerousCheckout parses the given workflow content and runs only
// RuleDangerousCheckout against it (via the linter's OnRulesCreated hook), returning the
// errors reported by that rule. Structural YAML/workflow syntax errors are treated as a
// test failure since every sample below is expected to be a valid workflow.
func lintDangerousCheckout(t *testing.T, content string) []*actionlint.Error {
	t.Helper()

	w, perrs := actionlint.Parse([]byte(content))
	if len(perrs) != 0 {
		t.Fatalf("unexpected parse errors: %v", perrs)
	}

	if w == nil {
		t.Fatal("workflow is nil after parsing")
	}

	rule := NewRuleDangerousCheckout(nil)

	v := actionlint.NewVisitor()
	v.AddPass(rule)

	if err := v.Visit(w); err != nil {
		t.Fatalf("unexpected visit error: %v", err)
	}

	return rule.Errs()
}

func assertDangerousCheckoutCount(t *testing.T, content string, want int) []*actionlint.Error {
	t.Helper()

	errs := lintDangerousCheckout(t, content)
	if len(errs) != want {
		t.Fatalf("expected %d dangerous-checkout error(s), got %d: %v", want, len(errs), errs)
	}

	return errs
}

// --- 1. Direct dangerous ref: unaffected by the fix, must stay flagged. ---

func TestDangerousCheckoutDirectHeadShaIsFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
	assertDangerousCheckoutCount(t, content, 1)
}

func TestDangerousCheckoutDirectHeadRefIsFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`
	assertDangerousCheckoutCount(t, content, 1)
}

// --- 2. Indirect dangerous ref, propagated through env/outputs: this is the false
// negative the fix must close. A naive fix that only special-cases literal "head.*"
// expressions (and treats every other dynamic expression as safe) would miss these,
// because "env.TARGET_REF" / "steps.prep.outputs.ref" never mention "head" textually.

func TestDangerousCheckoutIndirectEnvFromHeadIsFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: prepare
        run: |
          echo "TARGET_REF=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_ENV"
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ env.TARGET_REF }}
`
	assertDangerousCheckoutCount(t, content, 1)
}

func TestDangerousCheckoutIndirectStepOutputFromHeadIsFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: prepare
        id: prep
        run: |
          echo "ref=${{ github.event.pull_request.head.ref }}" >> "$GITHUB_OUTPUT"
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ steps.prep.outputs.ref }}
`
	assertDangerousCheckoutCount(t, content, 1)
}

// a job-level "env:" assigned straight from the head ref must taint every step in that
// job, without needing a $GITHUB_ENV write.
func TestDangerousCheckoutIndirectJobEnvFromHeadIsFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TARGET_REF: ${{ github.event.pull_request.head.sha }}
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ env.TARGET_REF }}
`
	assertDangerousCheckoutCount(t, content, 1)
}

// --- 3. Safe, protected-branch ref: this is the false positive the fix must remove. ---

func TestDangerousCheckoutHardcodedProtectedBranchIsNotFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: refs/heads/main
`
	assertDangerousCheckoutCount(t, content, 0)
}

func TestDangerousCheckoutHardcodedBranchNameIsNotFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: main
`
	assertDangerousCheckoutCount(t, content, 0)
}

func TestDangerousCheckoutBaseShaIsNotFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
`
	assertDangerousCheckoutCount(t, content, 0)
}

// an indirect chain is just as safe when it resolves to the base branch: the rule must
// trace it through env, not just blanket-flag every non-literal ref like the old
// implementation did.
func TestDangerousCheckoutIndirectEnvFromBaseIsNotFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: prepare
        run: |
          echo "TARGET_REF=${{ github.event.pull_request.base.sha }}" >> "$GITHUB_ENV"
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ env.TARGET_REF }}
`
	assertDangerousCheckoutCount(t, content, 0)
}

// same as above, but the intermediate env var is assigned a hardcoded literal instead of
// an expression.
func TestDangerousCheckoutIndirectEnvFromLiteralIsNotFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: prepare
        run: |
          echo "TARGET_REF=refs/heads/main" >> "$GITHUB_ENV"
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ env.TARGET_REF }}
`
	assertDangerousCheckoutCount(t, content, 0)
}

// --- regression guard: manual "git checkout"/"gh pr checkout" detection in run scripts
// is untouched by this fix. ---

func TestDangerousCheckoutManualGitCheckoutIsStillFlagged(t *testing.T) {
	content := `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        run: |
          git fetch origin pull/${{ github.event.pull_request.number }}/head
          git checkout $HEAD_SHA
`
	assertDangerousCheckoutCount(t, content, 1)
}

// --- an unrecognized dynamic ref keeps the rule's original conservative behaviour: we
// only special-case sources we can positively prove safe. ---

func TestDangerousCheckoutUnrecognizedDynamicRefIsFlagged(t *testing.T) {
	content := `
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ inputs.custom_ref }}
`
	assertDangerousCheckoutCount(t, content, 1)
}

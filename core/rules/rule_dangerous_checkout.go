package rules

import (
	"strings"

	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

/*
Judgment boundary for "actions/checkout" ref values (see also README.md#dangerous-checkout):

  - A ref value that contains no "${{ ... }}" expression (e.g. "main", "refs/heads/main",
    a commit sha typed in plain text) is a hardcoded value chosen by the workflow author.
    It is never attacker controlled, so it's always safe, regardless of its shape.
  - "github.event.pull_request.base.*" and "github.base_ref" always describe the base
    (target) repository, which is controlled by the repository owner. They are safe even
    on privileged triggers like "pull_request_target".
  - "github.event.pull_request.head.*" and "github.head_ref" describe the head (source)
    branch of the pull request. When the pull request comes from a fork, this is fully
    attacker controlled (this is what "head.repo.fork == true" means in practice); since
    static analysis cannot evaluate that boolean at lint time, any use of "head.*" is
    conservatively treated as untrusted.
  - "env.NAME" and "steps.<id>.outputs.<name>" are resolved by tracing, within the same
    job, how NAME/the output was last assigned (job-level "env:", or a "$GITHUB_ENV" /
    "$GITHUB_OUTPUT" write in a previous step's "run:" script). If that assignment is
    itself derived from "head.*" (directly, or transitively through another tainted
    env/output), the ref is untrusted. If the assignment can be proven safe (hardcoded
    value, or derived from "base.*"), the ref is safe.
  - Any other dynamic expression that cannot be classified by the rules above (e.g. an
    unrelated input, a secret, a step output we didn't see an assignment for) keeps the
    rule's original conservative behaviour and is flagged, since we cannot prove it safe.
*/

type RuleDangerousCheckout struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
	// envTaint tracks, for the job currently being visited, which environment variable
	// names are known to carry (or not carry) data derived from the pull request's head
	// branch. It's rebuilt from scratch for every job, since env var scope doesn't cross
	// job boundaries.
	envTaint map[string]bool
	// outputTaint is the step-output equivalent of envTaint, keyed by "<step_id>/<output_name>".
	outputTaint map[string]bool
}

// NewRuleDangerousCheckout creates new RuleDangerousCheckout instance.
func NewRuleDangerousCheckout(filterTriggers []string) *RuleDangerousCheckout {
	return &RuleDangerousCheckout{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-checkout",
			"Check for dangerous checkout.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDangerousCheckout) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *RuleDangerousCheckout) VisitJobPre(n *actionlint.Job) error {
	// env vars and step outputs are scoped to the job they are defined in: reset the
	// taint tracking state for every job instead of leaking it across jobs.
	rule.envTaint = map[string]bool{}
	rule.outputTaint = map[string]bool{}

	rule.collectEnvTaint(n.Env)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousCheckout) VisitStep(n *actionlint.Step) error {

	if rule.skip {
		return nil
	}

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.checkManualCheckout(e)
		rule.collectRunTaint(n, e)
	case *actionlint.ExecAction:
		rule.checkCheckoutAction(e)
	}

	return nil
}

func (rule *RuleDangerousCheckout) checkCheckoutAction(action *actionlint.ExecAction) {
	if action.Uses.ContainsExpression() {
		// Cannot parse specification made with interpolation. Give up
		return
	}

	spec := action.Uses.Value

	// search for checkout action
	if strings.HasPrefix(spec, "actions/checkout") {
		ref := action.Inputs["ref"]

		if ref != nil && rule.isValueUntrusted(ref.Value.Value) {
			rule.Errorf(
				ref.Value.Pos,
				"Use of 'actions/checkout' with a custom ref that can be controlled by the pull request's head branch.",
			)
		}
	}
}

// isValueUntrusted decides whether a raw YAML string (a checkout "ref:" input, or a
// value assigned to an env var / step output) is derived from the pull request's head
// branch. See the judgment boundary documented above the RuleDangerousCheckout type.
func (rule *RuleDangerousCheckout) isValueUntrusted(raw string) bool {
	if !containsExpression(raw) {
		// hardcoded value (branch name, full ref, sha, ...): never attacker controlled.
		return false
	}

	for _, expr := range extractExpressions(raw) {
		untrusted, recognized := rule.classifyExpr(expr)
		if !recognized || untrusted {
			return true
		}
	}

	return false
}

// classifyExpr inspects the content of a single "${{ ... }}" expression. recognized
// reports whether the expression matched one of the known source patterns (pull
// request base/head, env context, step outputs context); untrusted is only meaningful
// when recognized is true.
func (rule *RuleDangerousCheckout) classifyExpr(expr string) (untrusted bool, recognized bool) {
	switch {
	case common.TrustedPullRequestBaseRegexp.MatchString(expr):
		return false, true

	case common.UntrustedPullRequestHeadRegexp.MatchString(expr):
		return true, true

	case common.EnvContextRegexp.MatchString(expr):
		m := common.EnvContextRegexp.FindStringSubmatch(expr)

		return rule.envTaint[m[1]], true

	case common.StepOutputContextRegexp.MatchString(expr):
		m := common.StepOutputContextRegexp.FindStringSubmatch(expr)

		return rule.outputTaint[m[1]+"/"+m[2]], true

	default:
		return false, false
	}
}

// collectEnvTaint records, for every variable set by an "env:" block (job level, called
// from VisitJobPre), whether its value is untrusted.
func (rule *RuleDangerousCheckout) collectEnvTaint(env *actionlint.Env) {
	if env == nil || env.Vars == nil {
		return
	}

	for _, v := range env.Vars {
		rule.envTaint[v.Name.Value] = rule.isValueUntrusted(v.Value.Value)
	}
}

// collectRunTaint scans a "run:" script for "$GITHUB_ENV" / "$GITHUB_OUTPUT" writes and
// records the taint of the assigned value, so later steps in the same job that read
// "env.NAME" or "steps.<id>.outputs.NAME" can be traced back to this assignment.
func (rule *RuleDangerousCheckout) collectRunTaint(step *actionlint.Step, exec *actionlint.ExecRun) {
	script := exec.Run.Value

	for _, m := range common.GitHubEnvAssignRegexp.FindAllStringSubmatch(script, -1) {
		rule.envTaint[m[1]] = rule.isShellValueUntrusted(m[2])
	}

	if step.ID == nil {
		return
	}

	for _, m := range common.GitHubOutputAssignRegexp.FindAllStringSubmatch(script, -1) {
		rule.outputTaint[step.ID.Value+"/"+m[1]] = rule.isShellValueUntrusted(m[2])
	}
}

// isShellValueUntrusted is the shell-script equivalent of isValueUntrusted: it handles
// values written to $GITHUB_ENV/$GITHUB_OUTPUT, which may embed a "${{ ... }}"
// expression directly (e.g. `echo "ref=${{ github.event.pull_request.head.sha }}"`) or
// reference an already tainted env var through a shell variable (e.g. `echo "ref=$SHA"`
// after `SHA` was exported from a tainted env var).
func (rule *RuleDangerousCheckout) isShellValueUntrusted(value string) bool {
	if containsExpression(value) {
		return rule.isValueUntrusted(value)
	}

	for _, m := range common.ShellVarRefRegexp.FindAllStringSubmatch(value, -1) {
		if rule.envTaint[m[1]] {
			return true
		}
	}

	return false
}

func (rule *RuleDangerousCheckout) checkManualCheckout(action *actionlint.ExecRun) {
	rule.checkGitManualCheckout(action)
	rule.checkGHCliManualCheckout(action)
}

func (rule *RuleDangerousCheckout) checkGitManualCheckout(action *actionlint.ExecRun) {
	posArray := searchInScript(action.Run.Value, common.GitCheckoutBashRexexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Use of \"git checkout\" in a bash script with a potentially dangerous reference.",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("git checkout")
		exprError(&rule.RuleBase, err, action.Run.Pos.Line, action.Run.Pos.Col)
	}
}

func (rule *RuleDangerousCheckout) checkGHCliManualCheckout(action *actionlint.ExecRun) {
	posArray := searchInScript(action.Run.Value, common.GHCliCheckoutBashRexexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Use of \"gh pr checkout\" in a bash script with a potentially dangerous reference.",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("gh pr checkout")
		exprError(&rule.RuleBase, err, action.Run.Pos.Line, action.Run.Pos.Col)
	}
}

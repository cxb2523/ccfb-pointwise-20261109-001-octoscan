package common

import (
	_ "embed"
	"net/http"
	"os"
	"regexp"
	"time"
)

const (
	// ExitStatusSuccessNoProblem is the exit status when the command ran successfully with no problem found.
	ExitStatusSuccessNoProblem = 0
	// ExitStatusFailure is the exit status when the command stopped due to some fatal error while checking workflows.
	ExitStatusFailure = 1
	// ExitStatusSuccessProblemFound is the exit status when the command ran successfully with some problem found.
	ExitStatusSuccessProblemFound = 2
)

// regexp for rules

var StaticRefRegexp = regexp.MustCompile("^[a-zA-Z-]+$")
var GitHubOutputPwshRegexp = regexp.MustCompile(`(?m)(?i:env):GITHUB_OUTPUT`)
var GitHubOutputBashRegexp = regexp.MustCompile(`(?m)>>\s*"*\${*GITHUB_OUTPUT`)
var GitHubEnvPwshRegexp = regexp.MustCompile(`(?m)(?i:env):GITHUB_ENV`)
var GitHubEnvBashRexexp = regexp.MustCompile(`(?m)>{1,2}\s*"*\${*GITHUB_ENV`)
var BotActor = regexp.MustCompile(`(?m)github.(triggering_)?actor\s*?(=|!)=\s*?["'].*?\[bot\]`)

// GitCheckoutBashRexexp It’s not possible to include a backtick in a raw string literal (https://yourbasic.org/golang/multiline-string/)
var GitCheckoutBashRexexp = regexp.MustCompile(`(?m)git checkout.*(\$|` + regexp.QuoteMeta("`") + `)`)
var GHCliCheckoutBashRexexp = regexp.MustCompile(`(?m)gh pr checkout.*(\$|` + regexp.QuoteMeta("`") + `)`)
var GHCliDownloadArtifactsRexexp = regexp.MustCompile(`(?m)gh run download `)

// The following regexps are used by RuleDangerousCheckout (core/rules/rule_dangerous_checkout.go)
// to decide whether a "ref" used in "actions/checkout" (or an env/output value feeding
// into it) can be controlled by a pull request opened from a fork. They are only used by
// that rule and have no effect on the regexps above, which are shared with
// rule_dangerous_write.go and rule_dangerous_action.go.

// UntrustedPullRequestHeadRegexp matches expression fragments that read from the pull
// request's head branch (the contributor/fork side). On privileged triggers such as
// "pull_request_target" this data is attacker controlled.
var UntrustedPullRequestHeadRegexp = regexp.MustCompile(`(?i)github\.(event\.pull_request\.head|head_ref)\b`)

// TrustedPullRequestBaseRegexp matches expression fragments that read from the pull
// request's base branch (the target repository). This is set by the repository owner
// and is always safe, even on privileged triggers.
var TrustedPullRequestBaseRegexp = regexp.MustCompile(`(?i)github\.(event\.pull_request\.base|base_ref)\b`)

// EnvContextRegexp captures the variable name referenced through the "env" context,
// e.g. "env.TARGET_REF" captures "TARGET_REF".
var EnvContextRegexp = regexp.MustCompile(`\benv\.([A-Za-z_][A-Za-z0-9_]*)`)

// StepOutputContextRegexp captures the step id and output name referenced through the
// "steps" context, e.g. "steps.prep.outputs.ref" captures ("prep", "ref").
var StepOutputContextRegexp = regexp.MustCompile(`\bsteps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)`)

// GitHubEnvAssignRegexp matches a shell line that appends a NAME=VALUE pair to
// $GITHUB_ENV, capturing the variable name and the raw assigned value, e.g.
// `echo "TARGET_REF=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_ENV"`.
var GitHubEnvAssignRegexp = regexp.MustCompile(`(?m)echo\s+"?([A-Za-z_][A-Za-z0-9_]*)=([^"\n]*)"?\s*>>\s*"?\$\{?GITHUB_ENV`)

// GitHubOutputAssignRegexp is the $GITHUB_OUTPUT equivalent of GitHubEnvAssignRegexp.
var GitHubOutputAssignRegexp = regexp.MustCompile(`(?m)echo\s+"?([A-Za-z_][A-Za-z0-9_]*)=([^"\n]*)"?\s*>>\s*"?\$\{?GITHUB_OUTPUT`)

// ShellVarRefRegexp captures a shell variable reference such as "$FOO" or "${FOO}" so an
// indirect shell assignment like `TARGET=$HEAD_SHA` can be traced back to an env var.
var ShellVarRefRegexp = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// SyntaxCheckErrors crapy but I can't remove syntax-check errors, it's in the core of actionlint
var SyntaxCheckErrors = []string{
	"unexpected key \".+\" for ",
	"section is missing in workflow",
	"section should not be empty",
	"expected \".+\" key for \".+\" section but got",
	"section must be sequence node but",
	"is duplicated in workflow. previously defined at",
	"string should not be empty",
	"workflow is empty",
	" is duplicated in element of \".+\" section. previously defined at li",
	"step must run script with \".+\" section or run action wit",
	"section is missing in job",
	"could not parse as.+did not find expected",
	"is not available with \".+\". it is only available with",
	"expected scalar node for string value but found sequence node with",
	"sequence node but mapping node is expected",
	"please remove this section if it's unnecessary",
	"is only available for a reusable workflow call with",
	"previously defined at line",
	"could not parse as YAML",
	"it must be one of",
	"event must be one of",
	"this step is for running shell command since it contains",
	"scalar node but mapping node is expected",
	"section should have",
	"but found plain text node",
	"but found mapping node with",
	"section must be mapping",
	"should not be listed in",
	"must be greater than",
	"this step is for running action since it contains",
	"is required to run action",
}

var TriggerWithExternalData = []string{
	"issues", // might need to verify this one
	"issue_comment",
	"pull_request_target",
	"workflow_run",
}

var AllTriggers = []string{
	"branch_protection_rule",
	"check_run",
	"check_suite",
	"create",
	"delete",
	"deployment",
	"deployment_status",
	"discussion",
	"discussion_comment",
	"fork",
	"gollum",
	"issue_comment",
	"issues",
	"label",
	"merge_group",
	"milestone",
	"page_build",
	"project",
	"project_card",
	"project_column",
	"public",
	// "pull_request",
	"pull_request_comment",
	"pull_request_review",
	"pull_request_review_comment",
	"pull_request_target",
	"push",
	"registry_package",
	"release",
	"repository_dispatch",
	"schedule",
	"status",
	"watch",
	"workflow_call",
	"workflow_dispatch",
	"workflow_run",
}

//go:embed assets/sarif.template
var SarifTemplate []byte

func IsDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	return fileInfo.IsDir()
}

func IsStringInArray(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func IsInternetAvailable() error {
	url := "https://github.com"
	timeout := 5 * time.Second

	client := http.Client{
		Timeout: timeout,
	}

	// Create a new HTTP GET request to the specified URL
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	// Perform the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

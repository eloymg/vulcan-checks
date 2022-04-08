/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	report "github.com/adevinta/vulcan-report"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/avast/retry-go"
	"github.com/mcuadros/go-version"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	http "gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

const (
	vulnTruncateLimit   = 30
	vulnCVETrucateLimit = 10
)

var (
	checkName        = "vulcan-trivy"
	logger           = check.NewCheckLog(checkName)
	trivyCachePath   = "trivy_cache"
	reportOutputFile = "report.json"
)

type options struct {
	ForceUpdateDB bool   `json:"force_update_db"`
	IgnoreUnfixed bool   `json:"ignore_unfixed"`
	Severities    string `json:"severities"`
	Depth         int    `json:"depth"`
	Branch        string `json:"branch"`
}

type Results struct {
	Results ScanResponse `json:"Results"`
}

type ScanResponse []struct {
	Target          string `json:"Target"`
	Vulnerabilities []struct {
		VulnerabilityID  string   `json:"VulnerabilityID"`
		PkgName          string   `json:"PkgName"`
		InstalledVersion string   `json:"InstalledVersion"`
		FixedVersion     string   `json:"FixedVersion"`
		Title            string   `json:"Title,omitempty"`
		Description      string   `json:"Description,omitempty"`
		Severity         string   `json:"Severity"`
		References       []string `json:"References,omitempty"`
	} `json:"Vulnerabilities"`
}

type outdatedPackage struct {
	name     string
	version  string
	severity string
	fixedBy  string
	cves     []string
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	if target == "" {
		return errors.New("check target missing")
	}

	var opt options
	opt.Depth = 1
	opt.Branch = "main"
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	// We check if the target is not the public Github.
	targetURL, err := url.Parse(target)
	if err != nil {
		return err
	}

	// TODO: Support multiple authenticated Github Enterprise instances.
	githubURL, err := url.Parse(os.Getenv("GITHUB_ENTERPRISE_ENDPOINT"))
	if err != nil {
		return err
	}

	var auth *http.BasicAuth
	if githubURL.Host != "" && targetURL.Host == githubURL.Host {
		auth = &http.BasicAuth{
			Username: "username", // Can be anything except blank.
			Password: os.Getenv("GITHUB_ENTERPRISE_TOKEN"),
		}
	}

	gitCreds := &helpers.GitCreds{}
	if auth != nil {
		gitCreds.User = auth.Username
		gitCreds.Pass = auth.Password
	}
	isReachable, err := helpers.IsReachable(target, assetType, gitCreds)
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	repoPath := filepath.Join(os.TempDir(), "repo")
	if err := os.Mkdir(repoPath, 0755); err != nil {
		return err
	}

	co := git.CloneOptions{
		URL:   target,
		Auth:  auth,
		Depth: opt.Depth,
	}
	if opt.Branch != "" {
		co.ReferenceName = plumbing.ReferenceName(path.Join("refs/heads", opt.Branch))
	}
	_, err = git.PlainClone(repoPath, false, &co)
	if err != nil {
		return err
	}

	// Build trivy command with arguments.
	triviCmd := "trivy"
	triviArgs := []string{
		"--cache-dir", trivyCachePath,
		"fs",
		"-f", "json",
		"-o", reportOutputFile,
	}
	// Skip vulnerability db update if not explicitly forced.
	if !opt.ForceUpdateDB {
		triviArgs = append(triviArgs, "--skip-update")
		// Log warn if skip vulnerability db update and image tag is latest.
		if strings.HasSuffix(repoPath, "latest") {
			logger.Warnf("skipping vulnerability db update with latest tag: %s\n", target)
		}
	}

	// Show only vulnerabilities with fixes.
	if opt.IgnoreUnfixed {
		triviArgs = append(triviArgs, "--ignore-unfixed")
	}
	// Show only vulnerabilities with specific severities.
	if opt.Severities != "" {
		severitiesFlag := []string{"--severity", opt.Severities}
		triviArgs = append(triviArgs, severitiesFlag...)
	}
	// Append the target (repo cloned).
	triviArgs = append(triviArgs, repoPath)

	logger.Infof("running command: %s %s\n", triviCmd, triviArgs)

	err = retry.Do(
		func() error {
			cmd := exec.Command(triviCmd, triviArgs...)
			cmdOutput, err := cmd.CombinedOutput()
			if err != nil {
				logger.Errorf("exec.Command() failed with %s\nCommand output: %s\n", err, string(cmdOutput))
				return errors.New("trivy command execution failed")
			}
			logger.Infof("trivy command execution completed successfully")
			return nil
		},
		retry.Attempts(3),
		retry.DelayType(retry.RandomDelay),
		retry.MaxJitter(5*time.Second),
	)
	if err != nil {
		logger.Errorf("retry exec.Command() failed with error: %s\n", err)
		return errors.New("trivy command execution failed")
	}

	byteValue, err := ioutil.ReadFile(reportOutputFile)
	if err != nil {
		logger.Errorf("trivy report output file read failed with error: %s\n", err)
		return errors.New("trivy report output file read failed")
	}

	var results Results
	err = json.Unmarshal(byteValue, &results)
	if err != nil {
		return errors.New("unmarshal trivy output failed")
	}

	return processVulns(results.Results, target, state)

}

func processVulns(results ScanResponse, target string, state checkstate.State) error {
	// If there are no vulnerabilities we can return.
	if len(results) < 1 || len(results) == 1 && len(results[0].Vulnerabilities) == 0 {
		return nil
	}

	outdatedPackageVulns := make(map[string]outdatedPackage)
	for _, trivyTarget := range results {
		for _, dockerVuln := range trivyTarget.Vulnerabilities {
			op, ok := outdatedPackageVulns[dockerVuln.PkgName]
			if ok {
				if isMoreSevere(dockerVuln.Severity, op.severity) {
					op.severity = dockerVuln.Severity
				}
				if version.Compare(version.Normalize(dockerVuln.FixedVersion), version.Normalize(op.fixedBy), ">") {
					op.fixedBy = dockerVuln.FixedVersion
				}
			} else {
				op = outdatedPackage{
					name:     dockerVuln.PkgName,
					version:  dockerVuln.InstalledVersion,
					severity: dockerVuln.Severity,
					fixedBy:  dockerVuln.FixedVersion,
					cves:     []string{},
				}
			}

			op.cves = append(op.cves, dockerVuln.VulnerabilityID)

			outdatedPackageVulns[op.name] = op
		}
	}

	var opvArr []outdatedPackage
	for _, op := range outdatedPackageVulns {
		sort.Strings(op.cves)
		opvArr = append(opvArr, op)
	}

	// Sort outdated packages by severity, alphabetical order of the package
	// name and version.
	sort.Slice(opvArr, func(i, j int) bool {
		si := getScore(opvArr[i].severity)
		sj := getScore(opvArr[j].severity)
		switch {
		case si != sj:
			return si > sj
		case opvArr[i].name != opvArr[j].name:
			return opvArr[i].name < opvArr[j].name
		default:
			return opvArr[i].version < opvArr[j].version
		}
	})

	// To avoid report size overflow only top 30 most vulnerable packages
	// are reported.
	totalVulnerablePackages := len(opvArr)
	if totalVulnerablePackages > vulnTruncateLimit {
		logger.Warnf("truncate to top %d vulnerabilities\n", vulnTruncateLimit)
		opvArr = opvArr[0:vulnTruncateLimit]
	}

	vp := report.ResourcesGroup{
		Name: "Package Vulnerabilities",
		Header: []string{
			"Name",
			"Version",
			"FixedBy",
			"Vulnerabilities",
		},
	}
	for _, op := range opvArr {
		affectedResource := fmt.Sprintf("%s-%s", op.name, op.version)
		fingerprint := helpers.ComputeFingerprint(op.severity, op.cves)

		// Build vulnerabilities Rsources table.
		vResourcesTable := make(map[string]string)
		vResourcesTable["Name"] = op.name
		vResourcesTable["Version"] = op.version
		vResourcesTable["FixedBy"] = op.fixedBy

		for i := 0; i < len(op.cves) && i < vulnCVETrucateLimit; i++ {
			vResourcesTable["Vulnerabilities"] = fmt.Sprintf("%s | [%s](https://nvd.nist.gov/vuln/detail/%s)", vResourcesTable["Vulnerabilities"], op.cves[i], op.cves[i])
		}
		if len(op.cves) > vulnCVETrucateLimit {
			logger.Warnf("truncate affected package [%s] CVE list to [%d]\n", op.name, vulnCVETrucateLimit)
			vResourcesTable["Vulnerabilities"] = fmt.Sprintf("%s | and some others ...)", vResourcesTable["Vulnerabilities"])
		}

		vp.Rows = []map[string]string{vResourcesTable}

		// Build the vulnerability.
		vuln := report.Vulnerability{
			// Issue attributes.
			Summary:     "Outdated Packages in Git Repository",
			Description: "Vulnerabilities have been found in outdated packages in a code",
			Recommendations: []string{
				"Update affected packages to the versions specified in the resources table or newer.",
			},
			CWEID:  937,
			Labels: []string{"potential"},

			// Finding attributes.
			Fingerprint:      fingerprint,
			AffectedResource: affectedResource,
			Score:            getScore(op.severity),
			Details:          generateDetails(target),
			Resources:        []report.ResourcesGroup{vp},
		}

		state.AddVulnerabilities(vuln)
	}

	return nil
}

func generateDetails(target string) string {
	details := []string{
		"Run the following command to obtain the full report in your computer.",
		"docker run -it --rm -v $PWD:/local aquasec/trivy fs local",
	}
	return strings.Join(details, "\n")
}

func getScore(severity string) float32 {
	if severity == "CRITICAL" {
		return report.SeverityThresholdCritical
	}
	if severity == "HIGH" {
		return report.SeverityThresholdHigh
	}
	if severity == "MEDIUM" {
		return report.SeverityThresholdMedium
	}
	if severity == "LOW" {
		return report.SeverityThresholdLow
	}
	return report.SeverityThresholdNone
}

func isMoreSevere(s1, s2 string) bool {
	return getScore(s1) > getScore(s2)
}

/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	name = "vulcan-tls"

	analyzePath = "/opt/vulcan-tls/cipherscan/analyze.py"
	defaultPort = 443
)

var (
	connTimeout = 3 * time.Second

	inAWSELBPolicy = map[string]bool{
		"AES128-GCM-SHA256": true,
		"AES128-SHA256":     true,
		"AES256-GCM-SHA384": true,
		"AES256-SHA256":     true,
	}
)

type options struct {
	// Overwrite default port.
	Port string `json:"port"`
}

type result struct {
	Analysis *analysis `json:"analysis,omitempty"`
}

type failure struct {
	Risk   string
	Score  float32
	Issues []string
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLog(name)

		var opt options
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		if opt.Port != "" {
			target = fmt.Sprintf("%v:%v", target, opt.Port)
		} else {
			target = fmt.Sprintf("%v:%v", target, defaultPort)
		}

		// Check if the target accepts connections.
		conn, err := net.DialTimeout("tcp", target, connTimeout)
		if err != nil {
			// Nothing is listening in the target port.
			logger.WithError(err).Info("can not connect to the target port")
			return nil
		}
		if err := conn.Close(); err != nil {
			logger.WithError(err).Warn("test connection to the target port was not closed correctly")
		}

		output, _, err := command.Execute(
			ctx,
			nil,
			"python",
			[]string{
				analyzePath,
				"-o", "/usr/bin/openssl",
				"-l", "modern",
				"-t", target,
				"-j",
			}...,
		)
		if err != nil {
			return err
		}

		var a analysis
		if err := json.Unmarshal(output, &a); err != nil {
			return err
		}

		res := result{Analysis: &a}

		// Classify failures by risk on TLS security and severity.
		failures := []failure{
			{
				"minimally secure",
				report.SeverityThresholdMedium,
				res.Analysis.Failures.Vulnerable,
			},
			{
				"highly secure",
				report.SeverityThresholdLow,
				res.Analysis.Failures.Modern,
			},
		}

		for _, f := range failures {
			for _, s := range getWeakCiphersuites(f.Issues) {
				vuln := weakCiphersuitesVulnerability

				vuln.Score = f.Score
				vuln.Details = fmt.Sprintf("%v ciphersuite is not recommended for a %v encryption:\n", s, f.Risk)
				vuln.AffectedResource = fmt.Sprintf("%v / %v", target, s)
				vuln.Fingerprint = helpers.ComputeFingerprint(f.Score, f.Risk)

				state.AddVulnerabilities(vuln)
			}

			for _, s := range getWeakProtocols(f.Issues) {
				vuln := weakProtocolsVulnerability

				vuln.Score = f.Score
				vuln.Details = fmt.Sprintf("%v protocol is not recommended for a %v encryption", s, f.Risk)
				vuln.AffectedResource = fmt.Sprintf("%v / %v", target, s)
				vuln.Fingerprint = helpers.ComputeFingerprint(f.Score, f.Risk)

				state.AddVulnerabilities(vuln)
			}

			for _, s := range getMissingProtocols(f.Issues) {
				vuln := missingProtocolsVulnerability

				vuln.Score = f.Score
				vuln.Details = fmt.Sprintf("%v protocol is recommended for a %v encryption", s, f.Risk)
				vuln.AffectedResource = fmt.Sprintf("%v / %v", target, s)
				vuln.Fingerprint = helpers.ComputeFingerprint(f.Score, f.Risk)

				state.AddVulnerabilities(vuln)
			}

			for _, vuln := range getOtherVulnerabilities(f.Issues) {
				vuln.AffectedResource = target
				vuln.Fingerprint = helpers.ComputeFingerprint(vuln.Details, vuln.Recommendations)

				state.AddVulnerabilities(vuln)
			}
		}

		return nil
	}

	c := check.NewCheckFromHandler(name, run)
	c.RunAndServe()
}

func getWeakCiphersuites(failures []string) []string {
	var weakCiphersuites []string
	prefix := "remove cipher "
	for _, failure := range unique(failures) {
		if strings.HasPrefix(failure, prefix) {
			cipher := strings.TrimPrefix(failure, prefix)
			if strings.Contains(failure, "CHACHA20-POLY1305-OLD") || inAWSELBPolicy[cipher] {
				continue
			}
			weakCiphersuites = append(weakCiphersuites, cipher)
		}
	}
	return weakCiphersuites
}

func getWeakProtocols(failures []string) []string {
	var weakProtocols []string
	prefix := "disable "
	for _, failure := range unique(failures) {
		if strings.HasPrefix(failure, prefix) {
			weakProtocols = append(weakProtocols, strings.TrimPrefix(failure, prefix))
		}
	}
	return weakProtocols
}

func getMissingProtocols(failures []string) []string {
	var missingProtocols []string
	prefix := "consider enabling "
	for _, failure := range unique(failures) {
		if strings.HasPrefix(failure, prefix) {
			if strings.Contains(failure, "OCSP") {
				continue
			}
			missingProtocols = append(missingProtocols, strings.TrimPrefix(failure, prefix))
		}
	}
	return missingProtocols
}

func getOtherVulnerabilities(failures []string) []report.Vulnerability {
	vulnerabilities := []report.Vulnerability{}

	for _, failure := range unique(failures) {
		v := defaultVulnerability

		switch {
		case strings.HasPrefix(failure, "use a certificate signed with"):
			v.Summary = "Certificate Signed With Weak Algorithm"
			v.Description = "The algorithm used to sign the certificate for this site has known weakenesses."
			v.ImpactDetails = "It could be possible for attacker to generate a fraudulent certificate with a valid signature. Moreover, most modern clients will not trust this certificate."
		case strings.Contains(failure, "use DHE of at least 2048bits and ECC 256bit and greater"):
			v.Summary = "Perfect Forward Secrecy Not Supported"
			v.Description = "None of the ciphersuites supported by this site provide perfect forward secrecy."
			v.ImpactDetails = "The lack of perfect forward secrecy means that future compromise of encryption keys would mean that past communications are also compromised."
		case strings.Contains(failure, "consider enabling OCSP Stapling"):
			v.Summary = "OCSP Stapling Not Enabled"
			v.Description = "This site does not provide OCSP stapling, a mechanism that prevents clients from having to contact the CA each time the revocation status of the certificate needs to be verified."
			v.ImpactDetails = "By forcing clients to contact the CA to retrieve the revocation details of the certificate, the site is compromising their privacy, since every visit to the site is reported to the CA."
		case strings.Contains(failure, "fix ciphersuite ordering"):
			v.Summary = "Cipher Suite Order Not Compliant"
			v.Description = "The order of the supported ciphersuites is not compliant with the modern level."
			v.ImpactDetails = "Since stronger ciphersuites are not prioritized over weaker ones it is possible that, under some circumstances, a client will use a weaker ciphersuite over some available and suitable stronger ones."
		case strings.Contains(failure, "enforce") && strings.Contains(failure, "side ordering"):
			v.Summary = "Cipher Suite Ordering Not Enforced"
			v.Description = "This site does not enforce a specific priority order for its supported ciphersuites."
			v.ImpactDetails = "Since stronger ciphersuites are not prioritized over weaker ones it is possible that, under some circumstances, a client will use a weaker ciphersuite over some available and suitable stronger ones."
		case strings.Contains(failure, "don't use a cert with a bad signature algorithm"):
			v.Summary = "Bad Certificate Signature Algorithm"
		case strings.Contains(failure, "don't use a public key smaller than 2048 bits"):
			v.Summary = "Small Public Key"
		case strings.Contains(failure, "don't use an EC key smaller than 256 bits"):
			v.Summary = "Small Eliptic Curve Key"
		case strings.Contains(failure, "don't use DHE smaller than 1024bits or ECC smaller than 160bits"):
			v.Summary = "Small Diffie-Hellman Key"
		case strings.HasPrefix(failure, "increase priority"):
			// Already covered in Cipher Suite Order Not Compliant.
			continue
		case strings.Contains(failure, "don't use an untrusted or self-signed certificate"):
			// Overlaps with "vulcan-certinfo" check.
			continue
		case strings.HasPrefix(failure, "consider enabling "):
			// Overlaps with missing protocols.
			continue
		case strings.HasPrefix(failure, "remove cipher "):
			// Overlaps with weak ciphers.
			continue
		case strings.HasPrefix(failure, "disable "):
			// Overlaps with weak protocols.
			continue
		default:
			// Unknown vulnerability.
			v.Summary = "Unknown TLS Issue"
			v.Details = recommendation(failure)
		}

		if v.Summary != "Unknown TLS Issue" {
			v.Recommendations = append(v.Recommendations, recommendation(failure))
		}
		vulnerabilities = append(vulnerabilities, v)
	}

	return vulnerabilities
}

func recommendation(failure string) string {
	recommendation := []rune(failure)
	recommendation[0] = unicode.ToUpper(recommendation[0])
	return string(recommendation)
}

// Cipherscan returs some failures repeated for different standards.
func unique(stringSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

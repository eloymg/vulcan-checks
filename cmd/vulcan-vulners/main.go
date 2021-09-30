/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	gonmap "github.com/lair-framework/go-nmap"
)

const (
	defaultTiming = 4

	apiVersion      = "1.4"
	apiEndpointBase = "https://vulners.com/api/v3/burp/software/"
	apiEndpointFmt  = "%s?software=%s&version=%s&type=%s"

	// From https://cpe.mitre.org/specification/2.2/cpe-specification_2.2.pdf
	// page 28.
	cpeRegexStr = `^cpe:/[aho]?:[._\-~%0-9A-Za-z]*(?::[._\-~%0-9A-Za-z]*){0,5}$`
)

type options struct {
	// Nmap timing parameter.
	Timing int `json:"timing"`
	// Return status updates on the progress of the check
	ReportProgress bool `json:"report_progress"`
}

var (
	checkName = "vulcan-vulners"

	vulnersVuln = report.Vulnerability{
		Summary:     "Multiple vulnerabilities in %s",
		Description: "One or more vulnerabilities were detected in %s.",
		Score:       report.SeverityThresholdNone,
		Recommendations: []string{
			"If possible, restrict network access to the service.",
			"Check if the service has available security updates and apply them.",
			"When in doubt, check the resources linked below.",
		},
	}

	logger   *logrus.Entry
	cpeRegex *regexp.Regexp
)

func apiEndpoint(s, v, t string) string {
	return fmt.Sprintf(apiEndpointFmt, apiEndpointBase, s, v, t)
}

type vulnersResponse struct {
	Result string `json:"result"`
	Data   struct {
		Search []struct {
			Index  string  `json:"_index"`
			Type   string  `json:"_type"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source struct {
				Lastseen       string `json:"lastseen"`
				BulletinFamily string `json:"bulletinFamily"`
				Description    string `json:"description"`
				Modified       string `json:"modified"`
				ID             string `json:"id"`
				Href           string `json:"href"`
				Published      string `json:"published"`
				Title          string `json:"title"`
				Type           string `json:"type"`
				CVSS           struct {
					Score  float64 `json:"score"`
					Vector string  `json:"vector"`
				} `json:"cvss"`
			} `json:"_source"`
		} `json:"search"`
		Total int `json:"total"`
	} `json:"data"`
}

func severity(score float32) string {
	r := report.RankSeverity(score)

	switch r {
	case report.SeverityNone:
		return "Info"
	case report.SeverityLow:
		return "Low"
	case report.SeverityMedium:
		return "Medium"
	case report.SeverityHigh:
		return "High"
	case report.SeverityCritical:
		return "Critical"
	default:
		return "N/A"
	}
}

type vulnersFinding struct {
	Score     float32
	Resources report.ResourcesGroup
}

// buildVulnersFinding builds a vulners finding querying the vulners.com API. The
// resources of the finding contain the CVE'S found for the software component.
// The Score of the finding contains the highest score found in the all the
// CVE's.
func buildVulnersFinding(s, v, t string) (*vulnersFinding, error) {
	client := &http.Client{}
	endpoint := apiEndpoint(s, v, t)
	logger.Debugf("Using %s as endpoint", endpoint)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("can not create request: %w", err)
	}
	req.Header.Add("User-Agent", fmt.Sprintf("Vulners NMAP Plugin %s", apiVersion))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can not execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wrong status code: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading the reponse: %w", err)
	}

	logger.Debugf("Response from vulners.com API: %s", body)

	var b vulnersResponse
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("error decoding the reponse: %w", err)
	}

	if b.Result != "OK" {
		logger.Infof("result field in reponse is different than OK: %v", b.Result)
		return nil, nil
	}

	gr := report.ResourcesGroup{
		Name: "Findings",
		Header: []string{
			"CVE",
			"Severity",
			"Score",
			"Link",
		},
	}

	add := false
	var rows []map[string]string
	var score float32
	for _, e := range b.Data.Search {
		// NOTE (julianvilas): for now support just the CVE type. But would be good
		// to evaluate other types.
		if strings.ToLower(e.Source.Type) != "cve" {
			continue
		}

		add = true

		r := map[string]string{
			"CVE":      e.Source.ID,
			"Severity": severity(float32(e.Source.CVSS.Score)),
			"Score":    fmt.Sprintf("%.2f", e.Source.CVSS.Score),
			"Link":     e.Source.Href,
		}
		rows = append(rows, r)

		logger.WithFields(logrus.Fields{"resource": r}).Debug("Resource added")

		// score contains the max score found in all the CVE's of the finding.
		if float32(e.Source.CVSS.Score) > score {
			score = float32(e.Source.CVSS.Score)
		}
	}

	if !add {
		return nil, nil
	}

	// Sort by score and alphabetically.
	sort.Slice(rows, func(i, j int) bool {
		switch {
		case rows[i]["Score"] != rows[j]["Score"]:
			return rows[i]["Score"] > rows[j]["Score"]
		default:
			return rows[i]["CVE"] > rows[j]["CVE"]
		}
	})
	gr.Rows = rows

	f := vulnersFinding{
		Resources: gr,
		Score:     score,
	}
	logger.WithFields(logrus.Fields{"vulnersFindingAdded": f}).Debug("vulners finding added")

	return &f, nil
}

func findingByCPE(CPE string) (*vulnersFinding, error) {
	if !cpeRegex.MatchString(CPE) {
		return nil, fmt.Errorf("the CPE %s doesn't match the regex %s", CPE, cpeRegex)
	}

	parts := strings.Split(CPE, ":")

	// Skip if the type is not 'a' or there is not version.
	if parts[1] != "/a" || len(parts) < 5 || parts[4] == "" {
		logger.Debug("Skipping because of the given CPE")
		return nil, nil
	}

	return buildVulnersFinding(CPE, parts[4], "cpe")
}

func findingByProdVers(s, v, t string) (*vulnersFinding, error) {
	return buildVulnersFinding(s, v, t)
}

func computeVulnerabilityID(elems []string) string {
	h := sha256.New()

	sort.Strings(elems)

	for _, e := range elems {
		fmt.Fprintf(h, "%s - ", e)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func analyzeReport(target string, nmapReport *gonmap.NmapRun) ([]report.Vulnerability, error) {
	type vulnData struct {
		Vuln     report.Vulnerability
		CPEs     map[string]struct{}
		Products map[string]struct{}
	}
	uniqueVulns := map[string]vulnData{}

	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			logger.Debugf("Port detected: %d/%s", port.PortId, port.Protocol)

			done := false
			for _, cpe := range port.Service.CPEs {
				logger.Debugf("CPE found: %v", cpe)
				done = true
				f, err := findingByCPE(string(cpe))
				if err != nil {
					return nil, err
				}
				if f == nil {
					continue
				}
				summary := fmt.Sprintf(vulnersVuln.Summary, port.Service.Product)
				uniqueVulnId := fmt.Sprintf("CPE: %s, Port: %d/%s", string(cpe), port.PortId, port.Protocol)
				var cves []string

				for _, row := range f.Resources.Rows {
					cves = append(cves, row["CVE"])
				}
				v, ok := uniqueVulns[uniqueVulnId]
				if !ok {
					v.Vuln = report.Vulnerability{
						ID:               computeVulnerabilityID(cves),
						Summary:          summary,
						Description:      fmt.Sprintf(vulnersVuln.Description, port.Service.Product),
						Recommendations:  vulnersVuln.Recommendations,
						AffectedResource: fmt.Sprintf("CPE: %s, Port: %d/%s", string(cpe), port.PortId, port.Protocol),
					}
					v.CPEs = map[string]struct{}{}
					uniqueVulns[uniqueVulnId] = v
				}
				if _, ok := v.CPEs[string(cpe)]; !ok {
					v.CPEs[string(cpe)] = struct{}{}
					v.Vuln.Resources = append(v.Vuln.Resources, f.Resources)
					uniqueVulns[uniqueVulnId] = v
					if f.Score > v.Vuln.Score {
						v.Vuln.Score = f.Score
					}
				}
				v.Vuln.Details = fmt.Sprintf(
					"%sHost: %s\nPort: %d/%s\nProduct: %s\nVersion: %s\nCPEs: %v\n\n",
					v.Vuln.Details, host.Hostnames[0].Name, port.PortId, port.Protocol,
					port.Service.Product, port.Service.Version, port.Service.CPEs,
				)
				uniqueVulns[uniqueVulnId] = v
			}
			if done {
				continue
			}

			logger.Debugf("CPE not found, using product (%s) and version (%s) instead", port.Service.Product, port.Service.Version)

			if port.Service.Product == "" || port.Service.Version == "" {
				logger.Debug("Skip: Product or Version are empty")
				continue
			}

			f, err := findingByProdVers(port.Service.Product, port.Service.Version, "software")
			if err != nil {
				return nil, err
			}
			summary := fmt.Sprintf(vulnersVuln.Summary, port.Service.Product)
			productID := port.Service.Product + port.Service.Version
			uniqueVulnId := fmt.Sprintf("productID: %s, Port: %d/%s", productID, port.PortId, port.Protocol)
			var cves []string

			for _, row := range f.Resources.Rows {
				cves = append(cves, row["CVE"])
			}

			v, ok := uniqueVulns[uniqueVulnId]
			if !ok {
				v.Vuln = report.Vulnerability{

					ID:               computeVulnerabilityID(cves),
					Summary:          summary,
					Description:      fmt.Sprintf(vulnersVuln.Description, port.Service.Product),
					Score:            f.Score,
					Recommendations:  vulnersVuln.Recommendations,
					AffectedResource: fmt.Sprintf("CPE: %s, Port: %d/%s", productID, port.PortId, port.Protocol),
				}
				v.CPEs = map[string]struct{}{}
				uniqueVulns[uniqueVulnId] = v
			}
			if _, ok := v.Products[productID]; !ok {
				v.CPEs[productID] = struct{}{}
				v.Vuln.Resources = append(v.Vuln.Resources, f.Resources)
				uniqueVulns[uniqueVulnId] = v
				if f.Score > v.Vuln.Score {
					v.Vuln.Score = f.Score
				}
			}
			v.Vuln.Details = fmt.Sprintf(
				"%sHost: %s\nPort: %d/%s\nProduct: %s\nVersion: %s\nCPEs: %v\n\n",
				v.Vuln.Details, host.Hostnames[0].Name, port.PortId, port.Protocol,
				port.Service.Product, port.Service.Version, port.Service.CPEs,
			)
			uniqueVulns[uniqueVulnId] = v
		}
	}
	var vulns []report.Vulnerability
	for _, v := range uniqueVulns {
		vulns = append(vulns, v.Vuln)
	}
	return vulns, nil
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	l := check.NewCheckLog(checkName)
	logger = l.WithFields(logrus.Fields{"target": target, "assetType": assetType, "options": optJSON})

	if cpeRegex, err = regexp.Compile(cpeRegexStr); err != nil {
		return fmt.Errorf("regex can not be compiled. regex: %s, error: %v", cpeRegexStr, err)
	}

	var opt options
	if optJSON != "" {
		if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
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

	if opt.Timing == 0 {
		opt.Timing = defaultTiming
	}

	// Scan with version detection.
	// nmapParams := map[string]string{
	// 	"-Pn": "",
	// 	"-sV": "",
	// }

	serializedReport := `{
  "scanner": "nmap",
  "args": "nmap -oX - -T4 -Pn -sV --stats-every 1s localhost",
  "start": 1630399991,
  "startstr": "Tue Aug 31 10:53:11 2021",
  "version": "7.91",
  "profile_name": "",
  "xmloutputversion": "1.05",
  "scaninfo": {
    "type": "connect",
    "protocol": "tcp",
    "numservices": 1000,
    "services": "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389",
    "scanflags": ""
  },
  "verbose": {
    "level": 0
  },
  "debugging": {
    "level": 0
  },
  "taskbegin": null,
  "taskprogress": [
    {
      "task": "Service scan",
      "time": 1630399998,
      "percent": 0,
      "remaining": 0,
      "etc": -62135596800
    },
    {
      "task": "Service scan",
      "time": 1630400003,
      "percent": 50,
      "remaining": 12,
      "etc": 1630400014
    }
  ],
  "taskend": null,
  "prescripts": null,
  "postscripts": null,
  "hosts": [
    {
      "starttime": 1630399992,
      "endtime": 1630400003,
      "comment": "",
      "status": {
        "state": "up",
        "reason": "user-set",
        "reason_ttl": 0
      },
      "addresses": [
        {
          "addr": "127.0.0.1",
          "addrtype": "ipv4",
          "vendor": ""
        }
      ],
      "hostnames": [
        {
          "name": "localhost",
          "type": "user"
        },
        {
          "name": "localhost",
          "type": "PTR"
        }
      ],
      "smurfs": null,
      "ports": [
        {
          "protocol": "tcp",
          "id": 8088,
          "state": {
            "state": "open",
            "reason": "syn-ack",
            "reason_ttl": 0,
            "reason_ip": ""
          },
          "owner": {
            "name": ""
          },
          "service": {
            "name": "http",
            "conf": 10,
            "method": "probed",
            "version": "1.13.10",
            "product": "nginx",
            "extrainfo": "",
            "tunnel": "",
            "proto": "",
            "rpcnum": "",
            "lowver": "",
            "hiver": "",
            "hostname": "",
            "ostype": "",
            "devicetype": "",
            "servicefp": "",
            "cpes": [
              "cpe:/a:igor_sysoev:nginx:1.13.10"
            ]
          },
          "scripts": null
        },
        {
          "protocol": "tcp",
          "id": 8089,
          "state": {
            "state": "open",
            "reason": "syn-ack",
            "reason_ttl": 0,
            "reason_ip": ""
          },
          "owner": {
            "name": ""
          },
          "service": {
            "name": "http",
            "conf": 10,
            "method": "probed",
            "version": "1.13.10",
            "product": "nginx",
            "extrainfo": "",
            "tunnel": "",
            "proto": "",
            "rpcnum": "",
            "lowver": "",
            "hiver": "",
            "hostname": "",
            "ostype": "",
            "devicetype": "",
            "servicefp": "",
            "cpes": [
              "cpe:/a:igor_sysoev:nginx:1.13.10"
            ]
          },
          "scripts": null
        }
      ],
      "extraports": [
        {
          "state": "closed",
          "count": 998,
          "reasons": [
            {
              "reason": "conn-refused",
              "count": 998
            }
          ]
        }
      ],
      "os": {
        "portsused": null,
        "osmatches": null,
        "osfingerprints": null
      },
      "distance": {
        "value": 0
      },
      "uptime": {
        "seconds": 0,
        "lastboot": ""
      },
      "tcpsequence": {
        "index": 0,
        "difficulty": "",
        "vaules": ""
      },
      "ipidsequence": {
        "class": "",
        "values": ""
      },
      "tcptssequence": {
        "class": "",
        "values": ""
      },
      "hostscripts": null,
      "trace": {
        "proto": "",
        "port": 0,
        "hops": null
      },
      "times": {
        "srtt": "67",
        "rttv": "24",
        "to": "100000"
      }
    }
  ],
  "targets": null,
  "runstats": {
    "finished": {
      "time": 1630400003,
      "timestr": "Tue Aug 31 10:53:23 2021",
      "elapsed": 11.41,
      "summary": "Nmap done at Tue Aug 31 10:53:23 2021; 1 IP address (1 host up) scanned in 11.41 seconds",
      "exit": "success",
      "errormsg": ""
    },
    "hosts": {
      "up": 1,
      "down": 0,
      "total": 1
    }
  }
}`

	// nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, opt.ReportProgress, nmapParams)
	// nmapReport, _, err := nmapRunner.Run(ctx)
	var nmapReport *gonmap.NmapRun
	err = json.Unmarshal([]byte(serializedReport), &nmapReport)
	if err != nil {
		return err
	}

	vulns, err := analyzeReport(target, nmapReport)
	if err != nil {
		return err
	}

	state.AddVulnerabilities(vulns...)

	return nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

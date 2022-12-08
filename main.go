package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type InsepctorBaseFile struct {
	Findings []InspectorItem
}

type InspectorItem struct {
	Title                       string
	Description                 string
	Status                      string
	Severity                    string
	PackageVulnerabilityDetails struct {
		VulnerabilityId string
	}
	Remediation struct {
		Recommendation struct {
			Text string
		}
	}
	Resources []struct {
		Details struct {
			AwsEcrContainerImage struct {
				RepositoryName string
			}
			AwsEc2Instance struct {
				KeyName string
			}
		}
		Tags struct {
			Name string
		}
	}
}

type PrismBaseFile struct {
	Version int         `json:"version"`
	Issues  []PrismItem `json:"issues"`
}

type PrismItem struct {
	Name                    string      `json:"name"`
	OriginalRiskRating      string      `json:"original_risk_rating"`
	ClientDefinedRiskRating string      `json:"client_defined_risk_rating"`
	Finding                 string      `json:"finding"`
	Recommendation          string      `json:"recommendation"`
	AffectedHosts           []PrismHost `json:"affected_hosts"`
	Cves                    []string    `json:"cves"`
}

type PrismHost struct {
	Name string `json:"name"`
}

func main() {
	fmt.Println("Looking for Inspector File: inspector.json")

	inspectorResult := parseInspectorFile()
	prismResult := inspectorToPrism(inspectorResult)

	data, _ := json.Marshal(prismResult)

	f, _ := os.Create("prism.json")
	f.WriteString(string(data))
	f.Sync()
}

func parseInspectorFile() InsepctorBaseFile {
	jsonFile, err := os.Open("inspector.json")

	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("File found")
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var result InsepctorBaseFile
	json.Unmarshal([]byte(byteValue), &result)

	return result
}

func inspectorToPrism(baseFile InsepctorBaseFile) PrismBaseFile {
	var prismFile PrismBaseFile
	prismFile.Version = 1

	for _, finding := range baseFile.Findings {
		var prismItem PrismItem
		prismItem.Name = finding.Title
		prismItem.Finding = finding.Description
		prismItem.Recommendation = finding.Remediation.Recommendation.Text
		prismItem.ClientDefinedRiskRating = inspectorRatingToPrism(finding.Severity)
		prismItem.OriginalRiskRating = inspectorRatingToPrism(finding.Severity)

		if strings.Contains(finding.PackageVulnerabilityDetails.VulnerabilityId, "CVE-") {
			prismItem.Cves = append(prismItem.Cves, finding.PackageVulnerabilityDetails.VulnerabilityId)
		}

		var prismHost PrismHost

		if finding.Resources[0].Details.AwsEcrContainerImage.RepositoryName != "" {
			prismHost.Name = finding.Resources[0].Details.AwsEcrContainerImage.RepositoryName
		}

		if finding.Resources[0].Details.AwsEc2Instance.KeyName != "" {
			prismHost.Name = finding.Resources[0].Tags.Name
		}

		prismItem.AffectedHosts = append(prismItem.AffectedHosts, prismHost)
		prismFile.Issues = append(prismFile.Issues, prismItem)
	}

	return prismFile
}

func inspectorRatingToPrism(rating string) string {
	switch rating {
	case "INFORMATIONAL":
	case "UNTRIAGED":
		return "Info"
	case "LOW":
		return "Low"
	case "MEDIUM":
		return "Medium"
	case "HIGH":
		return "High"
	case "CRITICAL":
		return "Critical"
	}

	return "Info"
}

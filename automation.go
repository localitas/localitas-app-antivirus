package antivirus

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const scanAutomationName = "Antivirus: Managed FS Scan"

func RegisterScanAutomation(coreURL, token, appURL string) {
	if automationExists(coreURL, token, scanAutomationName) {
		log.Printf("✅ Antivirus scan automation already registered")
		return
	}

	body := map[string]interface{}{
		"name":        scanAutomationName,
		"description": "Periodically scans all files in managed Raft-backed filesystem for threats",
		"dag_config": map[string]interface{}{
			"dag_id":      "antivirus_managed_scan",
			"name":        "Antivirus: Managed FS Scan",
			"description": "Full scan of managed filesystem",
			"nodes": []map[string]interface{}{
				{
					"node_id":            "scan_managed_files",
					"node_type":          "http-api",
					"execution_strategy": "raft-leader",
					"metadata": map[string]interface{}{
						"url":             appURL + "/api/scan-managed-all",
						"method":          "POST",
						"body":            map[string]interface{}{},
						"timeout_ms":      600000,
						"max_retries":     1,
						"expected_status": 200,
					},
				},
			},
		},
		"trigger_type": "periodic",
		"trigger_config": map[string]interface{}{
			"periodic": map[string]interface{}{
				"schedule":    "0 2 * * *",
				"timezone":    "Local",
				"max_retries": 1,
			},
		},
		"is_enabled": true,
	}

	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", coreURL+"/apps/automation/api/automations", bytes.NewReader(b))
	if err != nil {
		log.Printf("⚠️  Failed to create scan automation request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("⚠️  Failed to register scan automation: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		log.Printf("✅ Registered managed FS scan automation (daily 2am)")
	} else {
		log.Printf("⚠️  Scan automation registration returned %d", resp.StatusCode)
	}
}

func automationExists(coreURL, token, name string) bool {
	req, err := http.NewRequest("GET", coreURL+"/apps/automation/api/automations", nil)
	if err != nil {
		return false
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var result struct {
		Automations []struct {
			Name string `json:"name"`
		} `json:"automations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	for _, a := range result.Automations {
		if a.Name == name {
			return true
		}
	}
	return false
}

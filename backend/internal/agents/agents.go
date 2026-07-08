package agents

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const OLLAMA_URL = "http://localhost:11434/api/generate"

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

// ReviewAgent reviews Nuclei findings to ensure 0% hallucination and provides a RAG-based analysis.
func ExploitReviewAgent(nucleiFindings []interface{}, techStack []interface{}, modelName string) (string, error) {
	if len(nucleiFindings) == 0 {
		return "No vulnerabilities found to review. The target appears secure based on the current scan signature set.", nil
	}

	// Prepare exact grounding context to avoid hallucination
	contextBytes, _ := json.MarshalIndent(nucleiFindings, "", "  ")
	techBytes, _ := json.MarshalIndent(techStack, "", "  ")

	prompt := fmt.Sprintf(`You are a world-class, military-grade Security Architect and Lead Penetration Tester.
Your task is to analyze the following technology stack and raw findings, and provide a contextual threat intelligence review.

CRITICAL INTEL INSTRUCTION (ZERO HALLUCINATION):
- Do NOT invent CVEs, software packages, or vulnerabilities. Only assess the provided context.
- You must critically analyze each finding to differentiate between:
  1. Benign System Services & Safe User Activities: E.g., normal system processes, local developer loops, standard web browsers (Safari, Chrome), local streaming (YouTube), or development databases bound to localhost. If they are safe, do NOT report them as vulnerabilities.
  2. Exposed Vulnerabilities & Active Attack Vectors: E.g., unpatched software, exposed database ports on public interfaces, unprotected administration panels, or active remote listener consoles (like Metasploit).
- For actual vulnerabilities, you MUST generate a safe, non-destructive Proof-of-Concept (PoC) exploit template (e.g., using curl, python, or raw requests) to let the security auditor safely verify the threat's existence without causing data loss or downtime.

TECHNOLOGY STACK:
%s

RAW FINDINGS (STRICT CONTEXT):
%s

Please structure your response precisely in this markdown format:
## 🛡️ Contextual Threat Intelligence Review

### 🟢 Benign System Services & Safe User Activities
(List the systems/ports running standard, benign services and explain why they are considered safe.)

### 🔴 Exposed Vulnerabilities & Active Threat Vectors
(List actual security risks. For each, include:
- Severity
- Safe Proof-of-Concept (PoC) verification commands/scripts
- Remediation steps)`, string(techBytes), string(contextBytes))

	reqBody := OllamaRequest{
		Model:  modelName, // Using the user-selected model dynamically
		Prompt: prompt,
		Stream: false,
	}

	jsonData, _ := json.Marshal(reqBody)

	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Post(OLLAMA_URL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("local AI not available (ensure Ollama is running): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("AI API returned status %d", resp.StatusCode)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	var ollamaResp OllamaResponse
	json.Unmarshal(body, &ollamaResp)

	return ollamaResp.Response, nil
}

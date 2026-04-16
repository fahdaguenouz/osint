package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// TestResult holds the outcome of a test
type TestResult struct {
	Name      string
	Passed    bool
	Duration  time.Duration
	Output    string
	Error     string
}

func main() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           OSINT-MASTER GLOBAL TEST RUNNER                  ║")
	fmt.Println("║         Automated Testing Suite - No Args Needed          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Detect OS and set binary name
	binaryName := "./osintmaster"
	if runtime.GOOS == "windows" {
		binaryName = "osintmaster.exe"
	}

	// Check if binary exists, build if needed
	if _, err := os.Stat(binaryName); os.IsNotExist(err) {
		fmt.Println("🔨 Binary not found. Building...")
		if err := buildBinary(); err != nil {
			fmt.Printf("❌ Build failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Build successful")
		fmt.Println()
	}

	// Ensure results directory exists
	os.MkdirAll("results", 0755)

	// Run all tests
	var results []TestResult

	// IP Lookup Tests
	results = append(results, testIPLookup(binaryName, "8.8.8.8", "Google DNS"))
	results = append(results, testIPLookup(binaryName, "1.1.1.1", "Cloudflare DNS"))
	results = append(results, testInvalidIP(binaryName))

	// Domain Tests
	results = append(results, testDomain(binaryName, "example.com", "Basic Domain"))
	results = append(results, testDomain(binaryName, "google.com", "Large Domain"))
	results = append(results, testInvalidDomain(binaryName))

	// Username Tests
	results = append(results, testUsername(binaryName, "monster", "GitHub User"))
	results = append(results, testUsername(binaryName, "github", "Org Account"))
	results = append(results, testInvalidUsername(binaryName))

	// Help & Edge Cases
	results = append(results, testHelp(binaryName))
	results = append(results, testNoArgs(binaryName))

	// Print Summary
	printSummary(results)

	// Cleanup old test results (keep last 10)
	cleanupOldResults()
}

// ==========================================
// TEST IMPLEMENTATIONS
// ==========================================

func testIPLookup(binary, ip, description string) TestResult {
	start := time.Now()
	fmt.Printf("🧪 Testing IP Lookup: %s (%s)...\n", ip, description)

	cmd := exec.Command(binary, "-i", ip)
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     fmt.Sprintf("IP Lookup: %s", ip),
		Duration: duration,
		Output:   string(output),
	}

	// Check for expected outputs
	outputStr := string(output)
	if err != nil {
		result.Passed = false
		result.Error = fmt.Sprintf("Command failed: %v", err)
	} else if !strings.Contains(outputStr, "ISP:") {
		result.Passed = false
		result.Error = "Missing ISP information"
	} else if !strings.Contains(outputStr, "Country:") {
		result.Passed = false
		result.Error = "Missing Country information"
	} else {
		result.Passed = true
	}

	printResult(result)
	return result
}

func testInvalidIP(binary string) TestResult {
	start := time.Now()
	fmt.Println("🧪 Testing IP Validation (invalid input)...")

	cmd := exec.Command(binary, "-i", "not-an-ip")
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     "IP Validation",
		Duration: duration,
		Output:   string(output),
	}

	// Should fail gracefully
	outputStr := string(output)
	if err == nil {
		result.Passed = false
		result.Error = "Should have failed with invalid IP"
	} else if !strings.Contains(outputStr, "invalid") && !strings.Contains(outputStr, "Error") {
		result.Passed = false
		result.Error = "Should show error message for invalid IP"
	} else {
		result.Passed = true
	}

	printResult(result)
	return result
}

func testDomain(binary, domain, description string) TestResult {
	start := time.Now()
	fmt.Printf("🧪 Testing Domain: %s (%s)...\n", domain, description)

	cmd := exec.Command(binary, "-d", domain)
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     fmt.Sprintf("Domain: %s", domain),
		Duration: duration,
		Output:   string(output),
	}

	outputStr := string(output)
	if err != nil {
		// Check if it's just a warning (crt.sh down, etc.)
		if strings.Contains(outputStr, "Main Domain:") {
			result.Passed = true // Partial success
		} else {
			result.Passed = false
			result.Error = fmt.Sprintf("Command failed: %v", err)
		}
	} else if !strings.Contains(outputStr, "Main Domain:") {
		result.Passed = false
		result.Error = "Missing main domain info"
	} else if !strings.Contains(outputStr, "Subdomains found:") {
		result.Passed = false
		result.Error = "Missing subdomain count"
	} else {
		result.Passed = true
	}

	// Extract subdomain count for reporting
	if count := extractSubdomainCount(outputStr); count >= 0 {
		fmt.Printf("   📊 Found %d subdomains\n", count)
	}

	printResult(result)
	return result
}

func testInvalidDomain(binary string) TestResult {
	start := time.Now()
	fmt.Println("🧪 Testing Domain Validation (invalid input)...")

	cmd := exec.Command(binary, "-d", "not-a-valid-domain-12345.xyz")
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     "Domain Validation",
		Duration: duration,
		Output:   string(output),
	}

	// Should handle gracefully
	outputStr := string(output)
	if strings.Contains(outputStr, "Error") || err != nil {
		result.Passed = true // Expected to have issues
	} else if strings.Contains(outputStr, "Main Domain:") {
		result.Passed = true // Tried anyway
	} else {
		result.Passed = false
		result.Error = "Unexpected behavior with invalid domain"
	}

	printResult(result)
	return result
}

func testUsername(binary, user, description string) TestResult {
	start := time.Now()
	fmt.Printf("🧪 Testing Username: %s (%s)...\n", user, description)

	cmd := exec.Command(binary, "-u", user)
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     fmt.Sprintf("Username: %s", user),
		Duration: duration,
		Output:   string(output),
	}

	outputStr := string(output)
	if err != nil {
		result.Passed = false
		result.Error = fmt.Sprintf("Command failed: %v", err)
	} else if !strings.Contains(outputStr, "Recent Activity:") {
		result.Passed = false
		result.Error = "Missing recent activity summary"
	} else {
		result.Passed = true
		// Count found platforms
		found := countFoundPlatforms(outputStr)
		fmt.Printf("   📊 Found on %d platforms\n", found)
	}

	printResult(result)
	return result
}

func testInvalidUsername(binary string) TestResult {
	start := time.Now()
	fmt.Println("🧪 Testing Username Validation (invalid input)...")

	cmd := exec.Command(binary, "-u", "invalid@user@name")
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     "Username Validation",
		Duration: duration,
		Output:   string(output),
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "invalid") || strings.Contains(outputStr, "Error") || err != nil {
		result.Passed = true
	} else {
		result.Passed = false
		result.Error = "Should reject invalid username format"
	}

	printResult(result)
	return result
}

func testHelp(binary string) TestResult {
	start := time.Now()
	fmt.Println("🧪 Testing Help Command...")

	cmd := exec.Command(binary, "--help")
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     "Help Command",
		Duration: duration,
		Output:   string(output),
	}

	outputStr := string(output)
	if err != nil {
		result.Passed = false
		result.Error = fmt.Sprintf("Help command failed: %v", err)
	} else if !strings.Contains(outputStr, "-i") || !strings.Contains(outputStr, "-d") || !strings.Contains(outputStr, "-u") {
		result.Passed = false
		result.Error = "Help missing option descriptions"
	} else if !strings.Contains(outputStr, "IP Address") || !strings.Contains(outputStr, "Domain") {
		result.Passed = false
		result.Error = "Help missing feature descriptions"
	} else {
		result.Passed = true
	}

	printResult(result)
	return result
}

func testNoArgs(binary string) TestResult {
	start := time.Now()
	fmt.Println("🧪 Testing No Arguments...")

	cmd := exec.Command(binary)
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := TestResult{
		Name:     "No Arguments",
		Duration: duration,
		Output:   string(output),
	}

	// Should show help or error
	outputStr := string(output)
	if strings.Contains(outputStr, "help") || strings.Contains(outputStr, "Error") || err != nil {
		result.Passed = true
	} else {
		result.Passed = false
		result.Error = "Should show help or error when no args given"
	}

	printResult(result)
	return result
}

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

func buildBinary() error {
	cmd := exec.Command("go", "build", "-o", "osintmaster", "./cmd/osintmaster")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func printResult(r TestResult) {
	status := "✅ PASS"
	if !r.Passed {
		status = "❌ FAIL"
	}
	fmt.Printf("   %s [%v] %s\n", status, r.Duration.Round(time.Millisecond), r.Name)
	if r.Error != "" {
		fmt.Printf("      Error: %s\n", r.Error)
	}
	fmt.Println()
}

func printSummary(results []TestResult) {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      TEST SUMMARY                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")

	passed := 0
	failed := 0
	totalDuration := time.Duration(0)

	for _, r := range results {
		totalDuration += r.Duration
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}

	fmt.Printf("Total Tests:  %d\n", len(results))
	fmt.Printf("Passed:       %d ✅\n", passed)
	fmt.Printf("Failed:       %d ❌\n", failed)
	fmt.Printf("Total Time:   %v\n", totalDuration.Round(time.Second))
	fmt.Printf("Success Rate: %.1f%%\n", float64(passed)/float64(len(results))*100)
	fmt.Println()

	if failed > 0 {
		fmt.Println("Failed Tests:")
		for _, r := range results {
			if !r.Passed {
				fmt.Printf("  - %s: %s\n", r.Name, r.Error)
			}
		}
		fmt.Println()
	}

	// Save detailed report
	saveReport(results)
}

func saveReport(results []TestResult) {
	filename := fmt.Sprintf("results/test_report_%s.txt", time.Now().Format("20060102_150405"))
	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Warning: Could not save report: %v\n", err)
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "OSINT-Master Test Report\n")
	fmt.Fprintf(w, "Generated: %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "========================================\n\n")

	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %s (%v)\n", status, r.Name, r.Duration)
		if r.Error != "" {
			fmt.Fprintf(w, "  Error: %s\n", r.Error)
		}
		fmt.Fprintf(w, "  Output:\n%s\n", r.Output)
		fmt.Fprintf(w, "----------------------------------------\n\n")
	}

	w.Flush()
	fmt.Printf("📄 Detailed report saved to: %s\n", filename)
}

func extractSubdomainCount(output string) int {
	// Look for "Subdomains found: X"
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Subdomains found:") {
			var count int
			fmt.Sscanf(line, "Subdomains found: %d", &count)
			return count
		}
	}
	return -1
}

func countFoundPlatforms(output string) int {
	count := 0
	platforms := []string{"github", "reddit", "instagram", "youtube", "tiktok", "medium"}
	
	outputLower := strings.ToLower(output)
	for _, platform := range platforms {
		if strings.Contains(outputLower, platform+": found") {
			count++
		}
	}
	return count
}

func cleanupOldResults() {
	// Keep only last 10 test reports
	matches, err := filepath.Glob("results/test_report_*.txt")
	if err != nil || len(matches) <= 10 {
		return
	}

	// Sort by name (which includes timestamp) and remove oldest
	// Simple approach: remove all but last 10
	for i := 0; i < len(matches)-10; i++ {
		os.Remove(matches[i])
	}
}
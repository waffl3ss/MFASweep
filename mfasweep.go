package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Color codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
)

// User agents for different platforms
var userAgents = map[string]string{
	"Windows":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56",
	"Linux":        "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:135.0) Gecko/20100101 Firefox/135.0",
	"MacOS":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.5 Safari/605.1.15",
	"Android":      "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Mobile Safari/537.36",
	"iPhone":       "Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Mobile/15E148 Safari/604.1",
	"WindowsPhone": "Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 635) like iPhone OS 7_0_3 Mac OS X AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537",
}

// Results tracking
type Results struct {
	GraphAPI        string
	AzureManagement string
	M365Windows     string
	M365Linux       string
	M365MacOS       string
	M365Android     string
	M365iPhone      string
	M365WinPhone    string
	EWS             string
	ActiveSync      string
	ADFS            string
}

// TokenInfo stores authentication tokens
type TokenInfo struct {
	Resource     string `json:"resource"`
	ClientID     string `json:"client_id"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Cookies      []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"cookies,omitempty"`
}

// RealmInfo for ADFS detection
type RealmInfo struct {
	XMLName       xml.Name `xml:"RealmInfo"`
	NameSpaceType string   `xml:"NameSpaceType"`
	AuthURL       string   `xml:"AuthUrl"`
	STSAuthURL    string   `xml:"STSAuthURL"`
	MEXURL        string   `xml:"MEXURL"`
}

const VERSION = "1.3.0"

var results Results
var tokenList []TokenInfo
var verbose bool

func main() {
	username := flag.String("username", "", "Email address to authenticate with (required)")
	password := flag.String("password", "", "Password for the account (required)")
	recon := flag.Bool("recon", false, "Perform ADFS recon only (no auth attempt)")
	checkADFSFlag := flag.Bool("adfs", false, "Check ADFS only (1 attempt)")
	includeADFS := flag.Bool("include-adfs", false, "Include ADFS when running -all")
	writeTokens := flag.Bool("write-tokens", false, "Write tokens to AccessTokens.json")
	skipConfirm := flag.Bool("y", false, "Skip confirmation prompt")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")

	// Individual check flags
	checkAll := flag.Bool("all", false, "Run all checks (10-11 auth attempts)")
	checkGraph := flag.Bool("graph", false, "Check Microsoft Graph API only (1 attempt)")
	checkAzure := flag.Bool("azure", false, "Check Azure Service Management API only (1 attempt)")
	checkEWSFlag := flag.Bool("ews", false, "Check Exchange Web Services only (1 attempt)")
	checkActiveSyncFlag := flag.Bool("activesync", false, "Check ActiveSync only (1 attempt)")
	checkWebPortal := flag.Bool("web", false, "Check M365 Web Portal - all user agents (6 attempts)")
	checkWebUA := flag.String("web-ua", "", "Check M365 Web Portal with specific UA (1 attempt): Windows|Linux|MacOS|Android|iPhone|WindowsPhone")

	flag.Parse()

	if *username == "" || *password == "" {
		fmt.Println("Usage: mfasweep -username <email> -password <password> [options]")
		fmt.Println()
		fmt.Println("Run all checks (10 auth attempts, 11 with -include-adfs):")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -all")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -all -include-adfs")
		fmt.Println()
		fmt.Println("Run single checks (1 auth attempt each):")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -graph")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -azure")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -ews")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -activesync")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -adfs")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -web-ua Windows")
		fmt.Println()
		fmt.Println("Run web portal checks (6 auth attempts):")
		fmt.Println("  mfasweep -username user@domain.com -password 'Pass123' -web")
		fmt.Println()
		fmt.Println("Recon only (0 auth attempts - just checks if ADFS is configured):")
		fmt.Println("  mfasweep -username user@domain.com -password dummy -recon")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Determine which checks to run
	runGraph := *checkAll || *checkGraph
	runAzure := *checkAll || *checkAzure
	runEWS := *checkAll || *checkEWSFlag
	runActiveSync := *checkAll || *checkActiveSyncFlag
	runADFS := (*checkAll && *includeADFS) || *checkADFSFlag
	runWebPortal := *checkAll || *checkWebPortal
	singleWebUA := *checkWebUA

	// If no specific check selected and not just recon, default to all checks
	noCheckSelected := !*checkGraph && !*checkAzure && !*checkEWSFlag && !*checkActiveSyncFlag && !*checkADFSFlag && !*checkWebPortal && *checkWebUA == "" && !*checkAll
	if noCheckSelected && !*recon {
		// Default to all checks if nothing specified
		runGraph = true
		runAzure = true
		runEWS = true
		runActiveSync = true
		runWebPortal = true
		if *includeADFS {
			runADFS = true
		}
	}

	// Initialize results
	results = Results{
		GraphAPI:        "NO",
		AzureManagement: "NO",
		M365Windows:     "NO",
		M365Linux:       "NO",
		M365MacOS:       "NO",
		M365Android:     "NO",
		M365iPhone:      "NO",
		M365WinPhone:    "NO",
		EWS:             "NO",
		ActiveSync:      "NO",
		ADFS:            "NO",
	}

	fmt.Printf("---------------- MFASweep (Go Edition) v%s ----------------\n", VERSION)

	var adfsURL string

	// Recon check (no auth attempt)
	if *recon {
		adfsURL = performRecon(*username)
		if adfsURL != "" && !runADFS && !*includeADFS {
			fmt.Print("Do you want to include ADFS authentication check? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			if response == "y" || response == "yes" {
				runADFS = true
			}
		}
		// If only recon was requested, exit
		if noCheckSelected {
			return
		}
	}

	// Count auth attempts
	authCount := 0
	if runGraph {
		authCount++
	}
	if runAzure {
		authCount++
	}
	if runEWS {
		authCount++
	}
	if runActiveSync {
		authCount++
	}
	if runADFS {
		authCount++
	}
	if singleWebUA != "" {
		authCount++
	} else if runWebPortal {
		authCount += 6
	}

	if authCount == 0 {
		fmt.Println("[*] No checks selected.")
		return
	}

	// Confirmation
	if !*skipConfirm {
		fmt.Printf(ColorYellow+"[*] WARNING: This will attempt to login to the %s account %d time(s).\n"+ColorReset, *username, authCount)
		fmt.Print("[*] This may lock out the account if credentials are incorrect. Continue? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println(ColorYellow + "[*] Stopping execution." + ColorReset)
			return
		}
	}

	checksRun := false

	// API authentication checks
	if runGraph || runAzure {
		fmt.Println()
		fmt.Println("=== Microsoft API Checks ===")
		if runGraph {
			checkGraphAPI(*username, *password, *writeTokens)
		}
		if runAzure {
			checkAzureManagementAPI(*username, *password, *writeTokens)
		}
		checksRun = true
	}

	// Web portal checks
	if singleWebUA != "" {
		fmt.Println()
		fmt.Println("")
		fmt.Println()
		fmt.Println("=== Microsoft Web Portal User Agent Check ===")
		if _, ok := userAgents[singleWebUA]; ok {
			checkM365WebPortal(*username, *password, singleWebUA, *writeTokens)
		} else {
			fmt.Printf(ColorRed+"[*] Unknown user agent: %s. Use: Windows, Linux, MacOS, Android, iPhone, WindowsPhone\n"+ColorReset, singleWebUA)
		}
		checksRun = true
	} else if runWebPortal {
		fmt.Println()
		fmt.Println("")
		fmt.Println()
		fmt.Println("=== Microsoft Web Portal User Agent Checks ===")
		for _, uaType := range []string{"Windows", "Linux", "MacOS", "Android", "iPhone", "WindowsPhone"} {
			checkM365WebPortal(*username, *password, uaType, *writeTokens)
		}
		checksRun = true
	}

	// Legacy auth checks
	if runEWS || runActiveSync {
		fmt.Println()
		fmt.Println("")
		fmt.Println()
		fmt.Println("=== Legacy Auth Checks ===")
		if runEWS {
			checkEWS(*username, *password)
		}
		if runActiveSync {
			checkActiveSync(*username, *password)
		}
		checksRun = true
	}

	// ADFS check
	if runADFS {
		fmt.Println()
		fmt.Println("")
		fmt.Println()
		fmt.Println("=== ADFS / Federation Check ===")
		checkADFS(*username, *password, adfsURL)
		checksRun = true
	}

	// Write tokens if requested
	if *writeTokens && len(tokenList) > 0 {
		writeTokensToFile()
	}

	// Print summary
	if checksRun {
		printResults(runADFS)
	}
}

func performRecon(username string) string {
	fmt.Println("---------------- Running recon checks ----------------")
	fmt.Println("[*] Checking if ADFS configured...")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=%s&xml=1", url.QueryEscape(username)))
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error checking ADFS: %v\n"+ColorReset, err)
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if verbose {
		fmt.Printf("[DEBUG] Realm response: %s\n", string(body))
	}

	var realmInfo RealmInfo
	if err := xml.Unmarshal(body, &realmInfo); err != nil {
		fmt.Printf(ColorRed+"[*] Error parsing ADFS response: %v\n"+ColorReset, err)
		return ""
	}

	if verbose {
		fmt.Printf("[DEBUG] NameSpaceType: %s, AuthURL: %s\n", realmInfo.NameSpaceType, realmInfo.AuthURL)
	}

	switch realmInfo.NameSpaceType {
	case "Federated":
		fmt.Println(ColorCyan + "[*] ADFS appears to be in use." + ColorReset)
		fmt.Printf(ColorCyan+"[*] ADFS authentication URL: %s\n"+ColorReset, realmInfo.AuthURL)
		return realmInfo.AuthURL
	case "Managed":
		fmt.Println(ColorCyan + "[*] ADFS does not appear to be in use. Authentication is managed by Microsoft." + ColorReset)
	case "Unknown":
		fmt.Println(ColorRed + "[*] Domain does not appear to have a presence in Microsoft Online / O365." + ColorReset)
	default:
		if verbose {
			fmt.Printf("[DEBUG] Unknown NameSpaceType: '%s'\n", realmInfo.NameSpaceType)
		}
	}

	return ""
}

func checkGraphAPI(username, password string, writeTokens bool) {
	fmt.Println()
	fmt.Println("---------------- Microsoft Graph API ----------------")
	fmt.Println(ColorYellow + "[*] Authenticating to Microsoft Graph API..." + ColorReset)

	clientID := "1b730954-1685-4b74-9bfd-dac224a7b894" // Azure AD PowerShell
	resource := "https://graph.windows.net"

	result, accessToken, refreshToken, errCode := performOAuthAuth(username, password, clientID, resource)

	if result == "success" {
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s was able to authenticate to %s\n"+ColorReset, username, resource)
		fmt.Println(ColorGreen + "[***] NOTE: The \"MSOnline\" PowerShell module should work here." + ColorReset)
		results.GraphAPI = "YES"

		if writeTokens {
			tokenList = append(tokenList, TokenInfo{
				Resource:     resource,
				ClientID:     clientID,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			})
		}
	} else {
		handleOAuthError(username, resource, errCode)
	}
}

func checkAzureManagementAPI(username, password string, writeTokens bool) {
	fmt.Println()
	fmt.Println("---------------- Azure Service Management API ----------------")
	fmt.Println(ColorYellow + "[*] Authenticating to Azure Service Management API..." + ColorReset)

	clientID := "1950a258-227b-4e31-a9cf-717495945fc2" // Azure PowerShell
	resource := "https://management.core.windows.net"

	result, accessToken, refreshToken, errCode := performOAuthAuth(username, password, clientID, resource)

	if result == "success" {
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s was able to authenticate to Azure Service Management API\n"+ColorReset, username)
		fmt.Println(ColorGreen + "[***] NOTE: The \"Az\" PowerShell module should work here." + ColorReset)
		results.AzureManagement = "YES"

		if writeTokens {
			tokenList = append(tokenList, TokenInfo{
				Resource:     resource,
				ClientID:     clientID,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			})
		}
	} else {
		handleOAuthError(username, "Azure Service Management API", errCode)
	}
}

func performOAuthAuth(username, password, clientID, resource string) (string, string, string, string) {
	client := &http.Client{Timeout: 30 * time.Second}

	data := url.Values{}
	data.Set("resource", resource)
	data.Set("client_id", clientID)
	data.Set("client_info", "1")
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)
	data.Set("scope", "openid")

	req, _ := http.NewRequest("POST", "https://login.microsoft.com/common/oauth2/token", strings.NewReader(data.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "error", "", "", err.Error()
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		var tokenResp map[string]interface{}
		json.Unmarshal(body, &tokenResp)
		accessToken, _ := tokenResp["access_token"].(string)
		refreshToken, _ := tokenResp["refresh_token"].(string)
		return "success", accessToken, refreshToken, ""
	}

	// Extract error code from response
	bodyStr := string(body)
	return "error", "", "", bodyStr
}

func handleOAuthError(username, resource, errResponse string) {
	switch {
	case strings.Contains(errResponse, "AADSTS50126"):
		fmt.Println(ColorRed + "[*] Login appears to have failed." + ColorReset)
	case strings.Contains(errResponse, "AADSTS50128") || strings.Contains(errResponse, "AADSTS50059"):
		fmt.Printf("[*] WARNING! Tenant for account %s doesn't exist.\n", username)
	case strings.Contains(errResponse, "AADSTS50034"):
		fmt.Printf("[*] WARNING! The user %s doesn't exist.\n", username)
	case strings.Contains(errResponse, "AADSTS50079") || strings.Contains(errResponse, "AADSTS50076"):
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s was able to authenticate to %s - NOTE: MFA (Microsoft) is in use.\n"+ColorReset, username, resource)
	case strings.Contains(errResponse, "AADSTS50158"):
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s was able to authenticate to %s - NOTE: Conditional access (MFA: DUO or other) is in use.\n"+ColorReset, username, resource)
	case strings.Contains(errResponse, "AADSTS50053"):
		fmt.Printf("[*] WARNING! The account %s appears to be locked.\n", username)
	case strings.Contains(errResponse, "AADSTS50057"):
		fmt.Printf("[*] WARNING! The account %s appears to be disabled.\n", username)
	case strings.Contains(errResponse, "AADSTS50055"):
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s was able to authenticate - NOTE: Password is expired.\n"+ColorReset, username)
	default:
		if verbose {
			fmt.Printf("[*] Got an unexpected error for user %s: %s\n", username, errResponse)
		} else {
			fmt.Println(ColorRed + "[*] Login appears to have failed." + ColorReset)
		}
	}
}

func checkM365WebPortal(username, password, uaType string, writeTokens bool) {
	fmt.Println()
	fmt.Printf("---------------- Microsoft 365 Web Portal w/ (%s) User Agent ----------------\n", uaType)
	fmt.Printf(ColorYellow+"[*] Authenticating to Microsoft 365 Web Portal using a (%s) user agent...\n"+ColorReset, uaType)

	userAgent := userAgents[uaType]

	jar, _ := cookiejar.New(nil)

	// Custom transport to avoid 417 errors (disable Expect: 100-continue)
	transport := &http.Transport{
		DisableKeepAlives:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 0, // Disable Expect: 100-continue
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Jar:       jar,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Get initial session - go directly to login.microsoftonline.com
	startURL := "https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&redirect_uri=https%3A%2F%2Foutlook.office365.com%2Fowa%2F&response_type=code&scope=openid&response_mode=form_post&nonce=placeholder&state=placeholder"

	req, _ := http.NewRequest("GET", startURL, nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error: %v\n"+ColorReset, err)
		return
	}

	// Follow redirects manually to get to the login page
	currentURL, _ := url.Parse(startURL)
	redirectCount := 0
	maxRedirects := 10

	for resp.StatusCode >= 300 && resp.StatusCode < 400 && redirectCount < maxRedirects {
		location := resp.Header.Get("Location")
		if location == "" {
			break
		}
		resp.Body.Close()
		redirectCount++

		// Handle relative URLs
		locURL, err := url.Parse(location)
		if err != nil {
			break
		}
		if !locURL.IsAbs() {
			locURL = currentURL.ResolveReference(locURL)
		}
		currentURL = locURL

		req, _ = http.NewRequest("GET", currentURL.String(), nil)
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		resp, err = client.Do(req)
		if err != nil {
			if verbose {
				fmt.Printf(ColorRed+"[*] Error following redirect: %v\n"+ColorReset, err)
			}
			fmt.Println(ColorRed + "[*] Login appears to have failed." + ColorReset)
			return
		}
	}

	// Check for error status codes
	if resp.StatusCode >= 400 {
		fmt.Printf(ColorRed+"[*] Login failed. (Status: %d)\n"+ColorReset, resp.StatusCode)
		resp.Body.Close()
		return
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	bodyStr := string(body)

	// Extract ctx, flowToken, and canary
	ctxRegex := regexp.MustCompile(`ctx=([^"&]+)`)
	flowTokenRegex := regexp.MustCompile(`"sFT":"([^"]+)"`)
	canaryRegex := regexp.MustCompile(`"canary":"([^"]+)"`)

	ctxMatch := ctxRegex.FindStringSubmatch(bodyStr)
	flowTokenMatch := flowTokenRegex.FindStringSubmatch(bodyStr)
	canaryMatch := canaryRegex.FindStringSubmatch(bodyStr)

	if len(ctxMatch) < 2 || len(flowTokenMatch) < 2 || len(canaryMatch) < 2 {
		fmt.Println(ColorRed + "[*] Could not extract authentication parameters. The login flow may have changed." + ColorReset)
		if verbose {
			fmt.Printf("[DEBUG] Response length: %d, Status: %d\n", len(bodyStr), resp.StatusCode)
			if len(bodyStr) < 500 {
				fmt.Printf("[DEBUG] Response body: %s\n", bodyStr)
			}
		}
		return
	}

	ctx := ctxMatch[1]
	flowToken := flowTokenMatch[1]
	canary := canaryMatch[1]

	// Step 2: Submit username
	credTypeData := map[string]interface{}{
		"username":                      username,
		"isOtherIdpSupported":           false,
		"checkPhones":                   false,
		"isRemoteNGCSupported":          true,
		"isCookieBannerShown":           false,
		"isFidoSupported":               true,
		"originalRequest":               ctx,
		"country":                       "US",
		"forceotclogin":                 false,
		"isExternalFederationDisallowed": false,
		"isRemoteConnectSupported":      false,
		"federationFlags":               0,
		"isSignup":                      false,
		"flowToken":                     flowToken,
		"isAccessPassSupported":         true,
	}
	credTypeJSON, _ := json.Marshal(credTypeData)

	req, _ = http.NewRequest("POST", "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US", strings.NewReader(string(credTypeJSON)))
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Step 3: Submit password
	authData := url.Values{}
	authData.Set("i13", "0")
	authData.Set("login", username)
	authData.Set("loginfmt", username)
	authData.Set("type", "11")
	authData.Set("LoginOptions", "3")
	authData.Set("passwd", password)
	authData.Set("ps", "2")
	authData.Set("canary", canary)
	authData.Set("ctx", ctx)
	authData.Set("flowToken", flowToken)
	authData.Set("NewUser", "1")
	authData.Set("fspost", "0")
	authData.Set("i21", "0")
	authData.Set("CookieDisclosure", "0")
	authData.Set("IsFidoSupported", "1")
	authData.Set("isSignupPost", "0")
	authData.Set("i2", "1")
	authData.Set("i19", "198733")

	req, _ = http.NewRequest("POST", "https://login.microsoftonline.com/common/login", strings.NewReader(authData.Encode()))
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error: %v\n"+ColorReset, err)
		return
	}
	defer resp.Body.Close()

	authBody, _ := io.ReadAll(resp.Body)
	authBodyStr := string(authBody)

	// Check for ESTSAUTH cookie
	loginURL, _ := url.Parse("https://login.microsoftonline.com")
	cookies := jar.Cookies(loginURL)
	hasESTSAUTH := false
	for _, cookie := range cookies {
		if cookie.Name == "ESTSAUTH" {
			hasESTSAUTH = true
			break
		}
	}

	if hasESTSAUTH {
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s was able to authenticate to the Microsoft 365 Web Portal. Checking MFA now...\n"+ColorReset, username)

		if strings.Contains(authBodyStr, "authMethodId") {
			fmt.Println(ColorRed + "[**] MFA is enabled and was required for this account." + ColorReset)
			mfaMethodRegex := regexp.MustCompile(`"authMethodId":"([^"]+)"`)
			if match := mfaMethodRegex.FindStringSubmatch(authBodyStr); len(match) > 1 {
				fmt.Printf(ColorYellow+"[***] MFA Method: %s\n"+ColorReset, match[1])
			}
		} else if strings.Contains(authBodyStr, "Stay signed in") {
			fmt.Println(ColorCyan + "[**] It appears there is no MFA required for this account." + ColorReset)
			fmt.Printf(ColorGreen+"[***] NOTE: Login with a web browser to https://outlook.office365.com using a %s user agent.\n"+ColorReset, uaType)
			setM365Result(uaType, "YES")
		} else if strings.Contains(authBodyStr, "Verify your identity") {
			fmt.Println(ColorRed + "[**] It appears MFA is setup for this account to access Microsoft 365 via the web portal." + ColorReset)
		} else {
			fmt.Println(ColorCyan + "[**] It appears there is no MFA required for this account." + ColorReset)
			fmt.Printf(ColorGreen+"[***] NOTE: Login with a web browser to https://outlook.office365.com using a %s user agent.\n"+ColorReset, uaType)
			setM365Result(uaType, "YES")
		}
	} else {
		fmt.Printf(ColorRed+"[*] Login appears to have failed. (Status: %d, No ESTSAUTH cookie)\n"+ColorReset, resp.StatusCode)
		if verbose {
			fmt.Printf("[DEBUG] Cookies received: ")
			for _, c := range cookies {
				fmt.Printf("%s ", c.Name)
			}
			fmt.Println()
		}
	}
}

func setM365Result(uaType, value string) {
	switch uaType {
	case "Windows":
		results.M365Windows = value
	case "Linux":
		results.M365Linux = value
	case "MacOS":
		results.M365MacOS = value
	case "Android":
		results.M365Android = value
	case "iPhone":
		results.M365iPhone = value
	case "WindowsPhone":
		results.M365WinPhone = value
	}
}

func checkEWS(username, password string) {
	fmt.Println()
	fmt.Println("---------------- Microsoft 365 Exchange Web Services ----------------")
	fmt.Println(ColorYellow + "[*] Authenticating to Microsoft 365 Exchange Web Services (EWS)..." + ColorReset)

	client := &http.Client{Timeout: 30 * time.Second}

	// Create Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	req, _ := http.NewRequest("GET", "https://outlook.office365.com/EWS/Exchange.asmx", nil)
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error: %v\n"+ColorReset, err)
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s successfully authenticated to Exchange Web Services.\n"+ColorReset, username)
		fmt.Println(ColorGreen + "[***] NOTE: EWS API access is available." + ColorReset)
		results.EWS = "YES"
	case 401:
		fmt.Printf(ColorRed+"[*] Login to EWS failed. (Status: %d - Basic Auth may be disabled)\n"+ColorReset, resp.StatusCode)
	case 456:
		// Microsoft returns 456 when basic auth is disabled at tenant level
		fmt.Printf(ColorRed+"[*] Login to EWS failed. (Status: %d - Basic Auth is disabled for this tenant)\n"+ColorReset, resp.StatusCode)
	default:
		fmt.Printf(ColorRed+"[*] Login to EWS failed. (Status: %d)\n"+ColorReset, resp.StatusCode)
	}
}

func checkActiveSync(username, password string) {
	fmt.Println()
	fmt.Println("---------------- Microsoft 365 ActiveSync ----------------")
	fmt.Println(ColorYellow + "[*] Authenticating to Microsoft 365 Active Sync..." + ColorReset)

	client := &http.Client{Timeout: 30 * time.Second}

	// Create Basic Auth header
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	req, _ := http.NewRequest("GET", "https://outlook.office365.com/Microsoft-Server-ActiveSync", nil)
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error: %v\n"+ColorReset, err)
		return
	}
	defer resp.Body.Close()

	// ActiveSync returns 505 on successful auth (HTTP Version Not Supported - but means creds worked)
	switch resp.StatusCode {
	case 505:
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s successfully authenticated to O365 ActiveSync.\n"+ColorReset, username)
		fmt.Println(ColorGreen + "[***] NOTE: The Windows 10 Mail app can connect to ActiveSync." + ColorReset)
		results.ActiveSync = "YES"
	case 401:
		fmt.Printf(ColorRed+"[*] Login to ActiveSync failed. (Status: %d - Invalid credentials or Basic Auth disabled)\n"+ColorReset, resp.StatusCode)
	case 403:
		fmt.Printf(ColorRed+"[*] Login to ActiveSync failed. (Status: %d - Access forbidden, may require device enrollment)\n"+ColorReset, resp.StatusCode)
	case 456:
		fmt.Printf(ColorRed+"[*] Login to ActiveSync failed. (Status: %d - Basic Auth is disabled for this tenant)\n"+ColorReset, resp.StatusCode)
	default:
		fmt.Printf(ColorRed+"[*] Login to ActiveSync failed. (Status: %d)\n"+ColorReset, resp.StatusCode)
	}
}

func checkADFS(username, password, adfsURL string) {
	fmt.Println()

	isRealADFS := false // Track if this is real ADFS (has AuthUrl) vs external IdP

	if adfsURL == "" {
		// Get ADFS URL
		fmt.Println("[*] Checking federation configuration...")
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=%s&xml=1", url.QueryEscape(username)))
		if err != nil {
			fmt.Printf(ColorRed+"[*] Error: %v\n"+ColorReset, err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if verbose {
			fmt.Printf("[DEBUG] Raw XML response:\n%s\n", bodyStr)
		}

		var realmInfo RealmInfo
		if err := xml.Unmarshal(body, &realmInfo); err != nil {
			fmt.Printf(ColorRed+"[*] Error parsing response: %v\n"+ColorReset, err)
			return
		}

		if realmInfo.NameSpaceType != "Federated" {
			fmt.Println(ColorCyan + "[*] Domain is not federated. Authentication is managed by Microsoft." + ColorReset)
			return
		}

		fmt.Println(ColorCyan + "[*] Domain is federated to an external Identity Provider." + ColorReset)

		// Check for AuthUrl (real ADFS with forms login)
		authURLRegex := regexp.MustCompile(`<AuthUrl>([^<]+)</AuthUrl>`)
		if match := authURLRegex.FindStringSubmatch(bodyStr); len(match) > 1 {
			adfsURL = match[1]
			isRealADFS = true
			fmt.Printf(ColorGreen+"[*] ADFS detected. Auth URL: %s\n"+ColorReset, adfsURL)
		} else if realmInfo.AuthURL != "" {
			adfsURL = realmInfo.AuthURL
			isRealADFS = true
			fmt.Printf(ColorGreen+"[*] ADFS detected. Auth URL: %s\n"+ColorReset, adfsURL)
		} else {
			// No AuthUrl - this is an external IdP (CyberArk, Okta, etc.), not traditional ADFS
			// Extract the IdP host from STSAuthURL if available
			var idpURL string
			stsRegex := regexp.MustCompile(`<STSAuthURL>([^<]+)</STSAuthURL>`)
			if match := stsRegex.FindStringSubmatch(bodyStr); len(match) > 1 {
				idpURL = match[1]
			} else if realmInfo.STSAuthURL != "" {
				idpURL = realmInfo.STSAuthURL
			}

			if idpURL != "" {
				parsedURL, _ := url.Parse(idpURL)
				if parsedURL != nil {
					fmt.Printf(ColorYellow+"[*] External IdP detected (not ADFS): %s\n"+ColorReset, parsedURL.Host)
					fmt.Printf("[*] IdP URL: %s\n", idpURL)
				}
			}
			fmt.Println(ColorYellow + "[*] This is not traditional ADFS - skipping forms-based auth check." + ColorReset)
			return
		}
	} else {
		isRealADFS = true // If URL was passed in, assume it's real ADFS
	}

	if adfsURL == "" {
		fmt.Println(ColorYellow + "[*] No ADFS URL found." + ColorReset)
		return
	}

	if !isRealADFS {
		return
	}

	fmt.Printf(ColorYellow+"[*] Attempting ADFS authentication at: %s\n"+ColorReset, adfsURL)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Get ADFS login page
	req, _ := http.NewRequest("GET", adfsURL, nil)
	req.Header.Set("User-Agent", userAgents["Windows"])

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error: %v\n"+ColorReset, err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Extract form action
	actionRegex := regexp.MustCompile(`action="([^"]+)"`)
	actionMatch := actionRegex.FindStringSubmatch(string(body))
	if len(actionMatch) < 2 {
		fmt.Println(ColorRed + "[*] Could not find ADFS login form." + ColorReset)
		return
	}

	adfsURLParsed, _ := url.Parse(adfsURL)
	authPath := actionMatch[1]
	fullADFSURL := fmt.Sprintf("https://%s%s", adfsURLParsed.Host, authPath)

	// Submit credentials
	authData := url.Values{}
	authData.Set("UserName", username)
	authData.Set("Password", password)
	authData.Set("AuthMethod", "FormsAuthentication")

	req, _ = http.NewRequest("POST", fullADFSURL, strings.NewReader(authData.Encode()))
	req.Header.Set("User-Agent", userAgents["Windows"])
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error: %v\n"+ColorReset, err)
		return
	}
	defer resp.Body.Close()

	authBody, _ := io.ReadAll(resp.Body)
	authBodyStr := string(authBody)

	// Check for MSISAUTH cookie
	adfsURLObj, _ := url.Parse(fullADFSURL)
	cookies := jar.Cookies(adfsURLObj)
	hasMSISAUTH := false
	for _, cookie := range cookies {
		if cookie.Name == "MSISAUTH" || cookie.Name == "MSISAuth" {
			hasMSISAUTH = true
			break
		}
	}

	if hasMSISAUTH {
		fmt.Printf(ColorGreen+"[*] SUCCESS! %s was able to authenticate to the ADFS Portal.\n"+ColorReset, username)

		if strings.Contains(authBodyStr, "Stay signed in") {
			fmt.Println(ColorCyan + "[**] It appears there is no MFA for this account." + ColorReset)
			fmt.Printf(ColorGreen+"[***] NOTE: Login with a web browser to %s\n"+ColorReset, fullADFSURL)
			results.ADFS = "YES"
		} else if strings.Contains(authBodyStr, "Verify your identity") {
			fmt.Println(ColorRed + "[**] It appears MFA is setup for this account to access Microsoft 365 via ADFS." + ColorReset)
		} else {
			fmt.Println(ColorCyan + "[**] Authentication successful. MFA status unclear." + ColorReset)
			results.ADFS = "YES"
		}
	} else {
		fmt.Printf(ColorRed+"[*] Login appears to have failed. (Status: %d)\n"+ColorReset, resp.StatusCode)
		if verbose {
			fmt.Printf("[DEBUG] Response length: %d\n", len(authBodyStr))
		}
	}
}

func writeTokensToFile() {
	data, _ := json.MarshalIndent(tokenList, "", "  ")
	err := os.WriteFile("AccessTokens.json", data, 0600)
	if err != nil {
		fmt.Printf(ColorRed+"[*] Error writing tokens: %v\n"+ColorReset, err)
	} else {
		fmt.Println(ColorCyan + "[*] Tokens written to AccessTokens.json" + ColorReset)
	}
}

func printResults(includeADFS bool) {
	fmt.Println()
	fmt.Println(ColorYellow + "######### SINGLE FACTOR ACCESS RESULTS #########" + ColorReset)

	type resultRow struct {
		Service string
		Result  string
	}

	rows := []resultRow{
		{"Microsoft Graph API", results.GraphAPI},
		{"Azure Service Management API", results.AzureManagement},
		{"M365 w/ Windows UA", results.M365Windows},
		{"M365 w/ Linux UA", results.M365Linux},
		{"M365 w/ MacOS UA", results.M365MacOS},
		{"M365 w/ Android UA", results.M365Android},
		{"M365 w/ iPhone UA", results.M365iPhone},
		{"M365 w/ Windows Phone UA", results.M365WinPhone},
		{"Exchange Web Services (BASIC Auth)", results.EWS},
		{"Active Sync (BASIC Auth)", results.ActiveSync},
	}

	if includeADFS {
		rows = append(rows, resultRow{"ADFS", results.ADFS})
	}

	// Find max service name length
	maxLen := 0
	for _, row := range rows {
		if len(row.Service) > maxLen {
			maxLen = len(row.Service)
		}
	}

	// Print results
	for _, row := range rows {
		padding := strings.Repeat(" ", maxLen-len(row.Service)+4)
		if row.Result == "YES" {
			fmt.Printf("%s%s| %s%s%s\n", row.Service, padding, ColorGreen, row.Result, ColorReset)
		} else {
			fmt.Printf("%s%s| %s\n", row.Service, padding, row.Result)
		}
	}
}

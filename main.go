package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// --- GRAFANA STRUCTS ---

// Team struct maps to the JSON response from the Grafana API
type Team struct {
	ID    int    `json:"id"`
	OrgID int    `json:"orgId"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// SearchTeamResponse matches the root object for /api/teams/search.
type SearchTeamResponse struct {
	Teams []Team `json:"teams"`
}

// TeamMember maps to a user in the /api/teams/:id/members response.
type TeamMember struct {
	UserID    int    `json:"userId"`
	Email     string `json:"email"`
	Login     string `json:"login"`
	AvatarURL string `json:"avatarUrl"`
	// TeamRole is the specific role within that team: 'Admin' or 'Member'
	TeamRole string `json:"teamRole"`
}

// AddMemberRequest is the structure for the POST request body.
type AddMemberRequest struct {
	UserID int `json:"userId"`
}

// User struct maps to a user entry from the /api/org/users response.
type OrgUser struct {
	OrgID      int    `json:"orgId"`
	UserID     int    `json:"userId"`
	Email      string `json:"email"`
	Login      string `json:"login"`
	Role       string `json:"role"` // The organization-level role (Viewer, Editor, Admin)
	LastSeenAt string `json:"lastSeenAt"`
}

// UserSearchResult matches a simplified user object returned by the Grafana user search API.
type UserSearchResult struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Login string `json:"login"`
}

// UserSearchResponse matches the root object for /api/users/search (requires Admin rights)
type UserSearchResponse struct {
	Users []UserSearchResult `json:"users"`
	// ... other fields like page, perPage, totalCount
}

// --- Keycloak Strucs ---

// GroupFull is the complete structure needed for recursive fetching and attribute checking.
type GroupFull struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	Path          string              `json:"path"`
	SubGroupCount int                 `json:"subGroupCount"`
	Attributes    map[string][]string `json:"attributes"` // Key for the check
	SubGroups     []GroupFull         `json:"subGroups"`  // Recursive array
}

// KeycloakTokenResponse (Used for authentication - Defined in previous answers)
type KeycloakTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// UserRepresentation is a simplified struct for Keycloak user data from the members endpoint
type UserRepresentation struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// --- CORE FUNCTIONS ---

func getTeamID(grafanaURL, authToken, teamName string) (int, error) {
	apiEndpoint := "/api/teams/search?name=" + teamName
	url := grafanaURL + apiEndpoint

	log.Debugf("INFO: Searching for team: %s", teamName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error sending request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("Grafana API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	var result SearchTeamResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("error decoding team search JSON: %w", err)
	}

	if len(result.Teams) == 0 {
		return 0, fmt.Errorf("team '%s' not found", teamName)
	}

	// Assuming the first match is the correct team
	return result.Teams[0].ID, nil
}

func listTeamMembers(grafanaURL, authToken string, teamID int) ([]TeamMember, error) {
	apiEndpoint := fmt.Sprintf("/api/teams/%d/members", teamID)
	url := grafanaURL + apiEndpoint

	log.Debugf("INFO: Fetching members for Team ID: %d", teamID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Grafana API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	var members []TeamMember
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("error decoding team members JSON: %w", err)
	}

	return members, nil
}

func addTeamMember(grafanaURL, authToken string, teamID int, userID int) error {
	// 1. Define API Endpoint
	apiEndpoint := fmt.Sprintf("/api/teams/%d/members", teamID)
	url := grafanaURL + apiEndpoint

	log.Debugf("INFO: Attempting to add User ID %d to Team ID %d...", userID, teamID)

	// 2. Prepare Request Body
	requestBody := AddMemberRequest{UserID: userID}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error marshalling JSON body: %w", err)
	}

	// 3. Create HTTP Request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating POST request: %w", err)
	}

	// 4. Set Headers
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// 5. Send Request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	// 6. Handle Response
	if resp.StatusCode == http.StatusOK {
		log.Debugf("SUCCESS: User ID %d successfully added to Team ID %d.", userID, teamID)
		return nil
	}
	if resp.StatusCode == http.StatusConflict { // 409 Conflict
		log.Debugf("WARNING: User ID %d is already a member of Team ID %d.", userID, teamID)
		return nil // Consider it a success if the user is already there
	}

	// Read and return error for all other non-200/409 codes
	bodyBytes, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("Grafana API returned unexpected status code: %d. Body: %s", resp.StatusCode, bodyBytes)
}

func listAllOrgUsers(grafanaURL, authToken string) ([]OrgUser, error) {
	// The API endpoint to get all users in the current organization
	const apiEndpoint = "/api/org/users"
	url := grafanaURL + apiEndpoint

	log.Debugf("INFO: Fetching all users in the current organization...")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Set Authorization header (Bearer Token)
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		// A 403 Forbidden often means the token doesn't have the Org Admin role.
		return nil, fmt.Errorf("Grafana API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	var users []OrgUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("error decoding organization users JSON: %w", err)
	}

	return users, nil
}

func removeTeamMember(grafanaURL, grafanaToken string, teamID int, userID int) error {
	// DELETE endpoint includes the Team ID and the User ID in the path: /api/teams/:teamId/members/:userId
	apiEndpoint := fmt.Sprintf("/api/teams/%d/members/%d", teamID, userID)
	url := grafanaURL + apiEndpoint

	log.Debugf("INFO: Attempting to remove User ID %d from Team ID %d...", userID, teamID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("error creating DELETE request: %w", err)
	}

	// Set Authorization header (Bearer Token)
	req.Header.Set("Authorization", "Bearer "+grafanaToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Printf("SUCCESS: User ID %d successfully removed from Team ID %d.", userID, teamID)
		return nil
	}
	// Note: You can treat 404 Not Found as success if the goal is just to ensure the user is not a member.

	bodyBytes, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("Grafana API returned unexpected status code: %d. Body: %s", resp.StatusCode, bodyBytes)
}

func getGrafanaUserIDByEmail(grafanaURL, username, password, email string) (int, error) {
	// Endpoint to search all users by email. The email must be URL-encoded.
	encodedEmail := url.QueryEscape(email)
	// Note: This endpoint often requires the token to have the Grafana Admin role.
	apiEndpoint := fmt.Sprintf("/api/users/search?query=%s", encodedEmail)
	url := grafanaURL + apiEndpoint

	log.Debugf("INFO: Looking up Grafana User ID for email: %s", email)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("error creating user search request: %w", err)
	}

	// Set Authorization header using Basic Auth with the token as username and empty password
	credentials := username + ":" + password
	encodedCredentials := base64.StdEncoding.EncodeToString([]byte(credentials))
	// 3. Set the Authorization header with the "Basic" scheme
	req.Header.Set("Authorization", "Basic "+encodedCredentials)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error sending user search request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("Grafana User Search API returned non-200 status: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	var searchResponse UserSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResponse); err != nil {
		return 0, fmt.Errorf("error decoding user search JSON: %w", err)
	}

	// Check results for exact match
	if len(searchResponse.Users) == 0 {
		return 0, fmt.Errorf("user with email %s not found in Grafana", email)
	}

	// We expect the first result to be the correct one if the search is specific enough
	// For safety, you might want to iterate and confirm an exact email match,
	// but the search endpoint typically filters well.
	return searchResponse.Users[0].ID, nil
}

// --- KEYCLOAK FUNCTIONS ---

// getAccessToken fetches a Keycloak Bearer token using the client_credentials grant type.
// The resulting token is required for all subsequent Admin API calls.
func getAccessToken(keycloakURL, realm, clientID, clientSecret string) (string, error) {
	// Construct the full URL for the token endpoint
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)
	log.Debugf("INFO: Requesting access token from: %s", tokenURL)

	// Prepare the body as URL-encoded form data (application/x-www-form-urlencoded)
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", clientID)
	// Keycloak will use the client_secret from the client's credentials/secret tab
	formData.Set("client_secret", clientSecret)

	// Create the HTTP POST Request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating token request: %w", err)
	}

	// Set the required content type header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the Request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending token request: %w", err)
	}
	defer resp.Body.Close()

	// Check for a non-200 status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	// Decode the JSON response
	var tokenResponse KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("error decoding token JSON: %w", err)
	}

	return tokenResponse.AccessToken, nil
}

// recursivelyFindTargetGroups is the core function.
// It fetches a group's children and recursively calls itself,
// filtering the results based on the presence of the required attribute.
func recursivelyFindTargetGroups(
	keycloakURL string,
	accessToken string,
	realm string,
	parentGroupID string,
	attrKey string,
) ([]GroupFull, error) {
	// Endpoint to get children of a specific group
	apiEndpoint := fmt.Sprintf("/admin/realms/%s/groups/%s/children?briefRepresentation=false", realm, parentGroupID)
	url := keycloakURL + apiEndpoint

	log.Debugf("INFO: Fetching children for Group ID: %s", parentGroupID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating children request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending children request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Keycloak API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	var childGroups []GroupFull
	if err := json.NewDecoder(resp.Body).Decode(&childGroups); err != nil {
		return nil, fmt.Errorf("error decoding children JSON: %w", err)
	}

	var targetGroups []GroupFull

	// Iterate through the children and apply the filter
	for _, group := range childGroups {
		// --- THE CRITICAL CHECK ---
		if _, exists := group.Attributes[attrKey]; exists {
			// 1. Group has the target attribute, so include it in the results
			targetGroups = append(targetGroups, group)
			log.Debugf("FOUND TARGET: %s (ID: %s) with attribute %s", group.Name, group.ID, attrKey)
		} else {
			// 2. Group does NOT have the attribute, so we skip it but check its children
			log.Debugf("INFO: Skipping group %s (No attribute %s), checking for children...", group.Name, attrKey)
		}

		// 3. Continue recursion if the current group has more children, regardless of attribute
		if group.SubGroupCount > 0 {
			nestedTargets, err := recursivelyFindTargetGroups(
				keycloakURL,
				accessToken,
				realm,
				group.ID,
				attrKey,
			)
			if err != nil {
				return nil, err // Bubble up error
			}
			targetGroups = append(targetGroups, nestedTargets...)
		}
	}

	return targetGroups, nil
}

// fetchFullGroupHierarchy starts the process by fetching top-level groups.
func fetchFullGroupHierarchy(keycloakURL, accessToken, realm, attrKey string) ([]GroupFull, error) {
	// Endpoint to get all top-level groups (briefRepresentation=false is needed to get SubGroupCount reliably)
	// NOTE: For some very old Keycloak versions, briefRepresentation=false might not be enough,
	// and you might need to try the ?search= workaround on this call too.
	groupsURL := fmt.Sprintf("%s/admin/realms/%s/groups?briefRepresentation=false", keycloakURL, realm)
	log.Debugf("INFO: Fetching top-level groups to start recursion...")

	// --- HTTP Request Setup (omitted for brevity, same structure as above) ---
	// Make request to groupsURL
	// Decode response into 'topLevelGroups []GroupFull'

	req, err := http.NewRequest("GET", groupsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating top-level request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending top-level request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Keycloak API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	var topLevelGroups []GroupFull
	if err := json.NewDecoder(resp.Body).Decode(&topLevelGroups); err != nil {
		return nil, fmt.Errorf("error decoding top-level groups JSON: %w", err)
	}

	var allTargetGroups []GroupFull

	// Start recursion for each top-level group
	for _, group := range topLevelGroups {

		// 1. CHECK TOP-LEVEL GROUP FIRST (Important for groups that are not nested)
		if _, exists := group.Attributes[attrKey]; exists {
			allTargetGroups = append(allTargetGroups, group)
			log.Debugf("FOUND TARGET: %s (ID: %s) at top level.", group.Name, group.ID)
		}

		// 2. RECURSE on the group's children if count is > 0
		if group.SubGroupCount > 0 {
			nestedTargets, err := recursivelyFindTargetGroups(
				keycloakURL,
				accessToken,
				realm,
				group.ID,
				attrKey,
			)
			if err != nil {
				return nil, err
			}
			allTargetGroups = append(allTargetGroups, nestedTargets...)
		}
	}

	return allTargetGroups, nil
}

func getGroupMembers(keycloakURL, realm, accessToken, groupID string) ([]UserRepresentation, error) {
	// Endpoint to get the direct members of the specified group ID
	apiEndpoint := fmt.Sprintf("/admin/realms/%s/groups/%s/members", realm, groupID)
	url := keycloakURL + apiEndpoint

	log.Debugf("INFO: Fetching members for Group ID: %s", groupID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating members request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending members request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Keycloak API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
	}

	var members []UserRepresentation
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("error decoding members JSON: %w", err)
	}

	return members, nil
}

func synchronizeTeamMembership(
	keycloakURL, grafanaURL, accessToken, grafanaToken, grafanaUsername, grafanaPassword, realm string,
	kcGroup GroupFull, // Keycloak group containing members and the Grafana Team ID
) error {
	// 1. Get the target Grafana Team ID from the Keycloak Group Attribute
	grafanaTeamIDStr, ok := kcGroup.Attributes["grafana-team-id"]
	if !ok || len(grafanaTeamIDStr) == 0 {
		return fmt.Errorf("group %s is missing 'grafana-team-id' attribute, cannot sync", kcGroup.Name)
	}

	// Get Team ID from grafanaTeamIDStr[0]
	teamID, err := getTeamID(grafanaURL, grafanaToken, grafanaTeamIDStr[0])
	if err != nil {
		return fmt.Errorf("error getting ID for team '%s': %v", grafanaTeamIDStr[0], err)
	}

	// Assuming the team ID is an integer; parse it.
	grafanaTeamID := teamID

	log.Debugf("\n--- Starting Sync: Keycloak Group '%s' -> Grafana Team ID %d ---\n", kcGroup.Name, grafanaTeamID)

	// --- STEP 1: Get Desired State (Keycloak Members) ---
	kcMembers, err := getGroupMembers(keycloakURL, realm, accessToken, kcGroup.ID)
	if err != nil {
		return fmt.Errorf("failed to retrieve Keycloak members: %w", err)
	}

	// Create a map for quick lookup: Email -> Keycloak User ID
	kcMemberMap := make(map[string]string) // Keycloak Email -> Keycloak User ID (string UUID)
	for _, member := range kcMembers {
		// Keycloak Admin API user IDs are typically GUID strings
		kcMemberMap[member.Email] = member.ID
	}
	log.Debugf("INFO: Keycloak has %d unique members (desired state).", len(kcMemberMap))

	// --- STEP 2: Get Current State (Grafana Members) ---
	// NOTE: We need a Grafana function to get the user's *Global* Grafana ID (int)
	// We'll assume a helper function exists for this, as Grafana TeamMember only gives Org/Team IDs.
	// For this example, let's assume `listTeamMembers` returns the necessary global UserID.

	// We must use the Grafana API to get the current member list (UserID, Email)
	// Note: We need the global Grafana User ID for the add/remove functions.
	// The listTeamMembers API usually returns `userId` (the global ID).
	grafanaMembers, err := listTeamMembers(grafanaURL, grafanaToken, grafanaTeamID)
	if err != nil {
		return fmt.Errorf("failed to retrieve current Grafana members: %w", err)
	}

	// Create a map for quick lookup: Email -> Grafana User ID
	grafanaMemberMap := make(map[string]int) // Grafana Email -> Grafana User ID (int)
	for _, member := range grafanaMembers {
		// Grafana API typically uses the Email/Login as a lookup key for sync logic
		grafanaMemberMap[member.Email] = member.UserID
	}
	log.Debugf("INFO: Grafana currently has %d members in team %d.", len(grafanaMemberMap), grafanaTeamID)

	// --- STEP 3: Reconcile and Execute Removals (Users NOT in Keycloak) ---
	usersRemoved := 0
	for email, grafanaUserID := range grafanaMemberMap {
		// If the user's email is NOT in the desired Keycloak list, remove them.
		if _, isKeycloakMember := kcMemberMap[email]; !isKeycloakMember {

			// Before removing, you MUST get the user's global Grafana User ID (int)
			// If listTeamMembers returns the UserID, we have it: grafanaUserID

			err := removeTeamMember(grafanaURL, grafanaToken, grafanaTeamID, grafanaUserID)
			if err != nil {
				log.Warnf("WARNING: Failed to remove user %s (ID %d) from Grafana: %v", email, grafanaUserID, err)
				continue
			}
			usersRemoved++
		}
	}

	// --- STEP 4: Reconcile and Execute Additions (Users in Keycloak but Missing in Grafana) ---
	usersAdded := 0
	for email := range kcMemberMap {
		// If the user's email is NOT in the current Grafana list, add them.
		if _, isGrafanaMember := grafanaMemberMap[email]; !isGrafanaMember {

			// CRITICAL STEP: Get the User's Global Grafana ID (int) from their Email/Login.
			// This requires an additional API call to Grafana's /api/users/lookup/:email.

			// **ASSUMPTION:** We assume a function `getGrafanaUserIDByEmail` exists.
			// In a real application, you must implement this lookup.
			grafanaUserID, err := getGrafanaUserIDByEmail(grafanaURL, grafanaUsername, grafanaPassword, email)
			if err != nil {
				log.Warnf("WARNING: Cannot add Keycloak user %s. Failed to look up global Grafana User ID: %v", email, err)
				continue
			}

			err = addTeamMember(grafanaURL, grafanaToken, grafanaTeamID, grafanaUserID)
			if err != nil {
				log.Warnf("WARNING: Failed to add user %s (ID %d) to Grafana: %v", email, grafanaUserID, err)
				continue
			}
			usersAdded++
		}
	}

	log.Infof("--- Sync Complete for Team ID %d. Added: %d, Removed: %d ---\n", grafanaTeamID, usersAdded, usersRemoved)
	return nil
}

func callProgram() {

	// 2. Configuration from Environment Variables
	grafanaURL := os.Getenv("GRAFANA_URL")
	authToken := os.Getenv("GRAFANA_TOKEN")
	authToken = strings.TrimSpace(authToken)
	authToken = strings.Trim(authToken, "\"") // Trim the double quote character

	const apiEndpoint = "/api/teams/search"

	// 3. Validation
	if grafanaURL == "" {
		log.Fatal("Error: GRAFANA_URL environment variable not set.")
	}
	if authToken == "" {
		log.Fatal("Error: GRAFANA_TOKEN environment variable not set.")
	}

	/*
		url := grafanaURL + apiEndpoint

		// The rest of the logic remains the same

		// 4. Create the HTTP Request
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatalf("Error creating request: %v", err)
		}

		// 5. Set the Authorization Header (Bearer Token)
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.Header.Set("Accept", "application/json")

		// 6. Send the Request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Error sending request to Grafana: %v", err)
		}
		defer resp.Body.Close()

		// 7. Handle the Response
		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Fatalf("Grafana API returned non-200 status code: %d. Body: %s", resp.StatusCode, bodyBytes)
		}

		// 8. Read and Decode the Body
		var result struct {
			Teams []Team `json:"teams"`
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading response body: %v", err)
		}

		if err := json.Unmarshal(body, &result); err != nil {
			log.Fatalf("Error unmarshalling JSON: %v", err)
		}

		// 9. Print the Team List
		fmt.Println("Successfully retrieved Grafana Teams:")
		fmt.Println("----------------------------------")
		for _, team := range result.Teams {
			// Iterate and print each team's details
			// STAGE 1: Find the Team ID
			teamID, err := getTeamID(grafanaURL, authToken, team.Name)
			if err != nil {
				log.Printf("Error getting ID for team '%s': %v", team.Name, err)
				continue
			}
			// STAGE 2: List the Team Members
			members, err := listTeamMembers(grafanaURL, authToken, teamID)
			if err != nil {
				log.Fatalf("Fatal: Failed to list team members: %v", err)
			}

			// STAGE 3: Print Results
			fmt.Printf("\n--- Members of Team: %s (ID: %d) ---\n", team.Name, teamID)
			if len(members) == 0 {
				fmt.Println("No members found in this team.")
				continue
			}

			for _, member := range members {
				fmt.Printf("User: %s (Login: %s) | Role: %s\n", member.Email, member.Login, member.TeamRole)
			}

			fmt.Println("----------------------------------")
		}

		// List all users in the organization
		// STAGE 1: List all Organization Users
		users, err := listAllOrgUsers(grafanaURL, authToken)
		if err != nil {
			log.Fatalf("Fatal: Failed to list organization users. Ensure your token has Org Admin privileges: %v", err)
		}

		// STAGE 2: Print Results
		fmt.Printf("\n--- All Users in Current Organization (%s) ---\n", grafanaURL)
		fmt.Printf("%-5s | %-20s | %-30s | %-10s | %s\n", "ID", "Login", "Email", "Role", "Last Seen")
		fmt.Println(strings.Repeat("-", 80))

		for _, user := range users {
			fmt.Printf("%-5d | %-20s | %-30s | %-10s | %s\n",
				user.UserID,
				user.Login,
				user.Email,
				user.Role,
				user.LastSeenAt)
		}

		fmt.Println(strings.Repeat("-", 80))
	*/

	// KEYCLOAK SYNCING LOGIC (EXAMPLE USAGE)
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	realm := os.Getenv("KEYCLOAK_REALM")
	keycloakClientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	keycloakClientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")

	const targetAttribute = "grafana-team-id" // The attribute key to check for

	// STAGE 1: Get Access Token
	accessToken, err := getAccessToken(
		keycloakURL,
		realm,
		keycloakClientID,
		keycloakClientSecret,
	)
	if err != nil {
		log.Fatalf("Fatal: Failed to get Keycloak access token: %v", err)
	}

	// STAGE 2: Fetch and Filter Groups
	targetGroups, err := fetchFullGroupHierarchy(
		keycloakURL,
		accessToken,
		realm,
		targetAttribute,
	)
	if err != nil {
		log.Fatalf("Fatal: Failed to fetch and filter groups: %v", err)
	}

	// STAGE 3: Print Results
	log.Debugf("\n--- Found %d Keycloak Groups for Grafana Sync ---\n", len(targetGroups))
	for _, group := range targetGroups {
		log.Debugf("\nProcessing Team: %s\n", group.Name)

		// Call the new function to get the list of users for this specific group
		members, err := getGroupMembers(keycloakURL, realm, accessToken, group.ID)
		if err != nil {
			log.Errorf("ERROR: Could not fetch members for %s: %v", group.Name, err)
			continue // Skip this group and move to the next one
		}

		log.Debugf("  Found %d direct members.\n", len(members))

		for _, member := range members {
			log.Debugf("    - User: %s (Email: %s)\n", member.Username, member.Email)
		}

		// --- Synchronization Step ---
		// At this point, you would call your Grafana API logic:
		// 1. Get current Grafana team members (for the team linked via the grafana-team-id attribute).
		// 2. Compare 'members' (Keycloak) vs. 'current' (Grafana).
		// 3. Call addTeamMember() or removeTeamMember() as needed.
		grafanaUser := os.Getenv("GRAFANA_USER")
		grafanaPass := os.Getenv("GRAFANA_PASS")

		err =
			synchronizeTeamMembership(keycloakURL, grafanaURL, accessToken, authToken, grafanaUser, grafanaPass, realm, group)
		if err != nil {
			log.Errorf("ERROR: Synchronization failed for group %s: %v", group.Name, err)
		}
	}

	// Stage 4: Perform Synchronization for Each Group
	log.Debugf("\n--- Script Complete ---")
}

// Log is the global logger instance
var log = logrus.New()

func init() {
	// 1. Load .env file
	// godotenv.Load() will look for a file named .env in the current directory
	err := godotenv.Load()
	if err != nil {
		log.Warnf("Note: No .env file found. Falling back to system environment variables.")
	}

	// Set the minimum level to display (e.g., only show Warning and above)
	logLevelStr := os.Getenv("LOG_LEVEL")
	switch strings.ToLower(logLevelStr) {
	case "debug":
		fmt.Print("Setting log level to DEBUG\n")
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn", "warning":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	case "fatal":
		log.SetLevel(logrus.FatalLevel)
	case "panic":
		log.SetLevel(logrus.PanicLevel)
	default:
		log.SetLevel(logrus.InfoLevel) // Default to Info if not set or unrecognized
	}

	// Set the output format (e.g., JSON or Text)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Warnf("Note: No .env file found. Falling back to system environment variables.")
	}

	// Call the main program function to execute the logic scheduled every minute
	log.Info("Starting Go scheduler to run task every minute...")

	// 1. Create a Ticker that ticks every 30 seconds.
	syncTimeStr := os.Getenv("SYNC_TIME")
	var syncTime int
	if syncTimeStr == "" {
		log.Warn("SYNC_TIME environment variable not set. Using Default: 30s")
		syncTime = 30
	} else {
		parsed, err := strconv.Atoi(syncTimeStr)
		if err != nil {
			log.Warnf("Invalid SYNC_TIME value '%s'. Using Default: 30s", syncTimeStr)
			syncTime = 30
		} else {
			syncTime = parsed
		}
	}
	ticker := time.NewTicker(time.Duration(syncTime) * time.Second)

	// 2. Set up a deferred function to stop the ticker when main() exits.
	defer ticker.Stop()

	// 3. Run the task immediately once at the start (optional).
	callProgram()

	// 4. Start an infinite loop that waits for the Ticker channel.
	// The 'select {}' block prevents the main function from exiting.
	for range ticker.C {
		// The channel sends a signal every minute.
		callProgram()
	}

}

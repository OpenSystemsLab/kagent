package supabase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AuthClient handles Supabase Auth operations
type AuthClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewAuthClient creates a new Supabase Auth client
func NewAuthClient(baseURL, apiKey string) *AuthClient {
	return &AuthClient{
		baseURL: fmt.Sprintf("%s/auth/v1", baseURL),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SignUpRequest represents a sign up request
type SignUpRequest struct {
	Email    string                 `json:"email"`
	Password string                 `json:"password"`
	Phone    string                 `json:"phone,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// SignInRequest represents a sign in request
type SignInRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Token    string `json:"token,omitempty"`
	Type     string `json:"type,omitempty"` // sms, email, etc.
}

// User represents a Supabase user
type User struct {
	ID                 string                 `json:"id"`
	Aud                string                 `json:"aud"`
	Role               string                 `json:"role"`
	Email              string                 `json:"email"`
	EmailConfirmedAt   *time.Time             `json:"email_confirmed_at"`
	Phone              string                 `json:"phone"`
	PhoneConfirmedAt   *time.Time             `json:"phone_confirmed_at"`
	ConfirmationSentAt *time.Time             `json:"confirmation_sent_at"`
	RecoverySentAt     *time.Time             `json:"recovery_sent_at"`
	EmailChangeSentAt  *time.Time             `json:"email_change_sent_at"`
	NewEmail           string                 `json:"new_email"`
	InvitedAt          *time.Time             `json:"invited_at"`
	ActionLink         string                 `json:"action_link"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	UserMetadata       map[string]interface{} `json:"user_metadata"`
	AppMetadata        map[string]interface{} `json:"app_metadata"`
	Identities         []Identity             `json:"identities"`
}

// Identity represents a user identity
type Identity struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	IdentityData struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	} `json:"identity_data"`
	Provider     string    `json:"provider"`
	LastSignInAt time.Time `json:"last_sign_in_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session represents a user session
type Session struct {
	AccessToken          string `json:"access_token"`
	TokenType            string `json:"token_type"`
	ExpiresIn            int    `json:"expires_in"`
	ExpiresAt            int64  `json:"expires_at"`
	RefreshToken         string `json:"refresh_token"`
	User                 *User  `json:"user"`
	ProviderToken        string `json:"provider_token,omitempty"`
	ProviderRefreshToken string `json:"provider_refresh_token,omitempty"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	RefreshToken string   `json:"refresh_token"`
	User         *User    `json:"user"`
	Session      *Session `json:"session"`
}

// SignUp creates a new user (simplified implementation)
func (ac *AuthClient) SignUp(ctx context.Context, req *SignUpRequest) (*AuthResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ac.baseURL+"/signup", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("apikey", ac.apiKey)

	resp, err := ac.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signup failed: %s", string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	return &authResp, nil
}

// SignIn authenticates a user (simplified implementation)
func (ac *AuthClient) SignIn(ctx context.Context, req *SignInRequest) (*AuthResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", ac.baseURL+"/token?grant_type=password", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("apikey", ac.apiKey)

	resp, err := ac.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("signin failed: %s", string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, err
	}

	return &authResp, nil
}

// SignOut signs out a user
func (ac *AuthClient) SignOut(ctx context.Context, accessToken string) error {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", ac.baseURL+"/logout", nil)
	if err != nil {
		return err
	}

	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("apikey", ac.apiKey)

	resp, err := ac.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// GetUser gets user information from access token
func (ac *AuthClient) GetUser(ctx context.Context, accessToken string) (*User, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", ac.baseURL+"/user", nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("apikey", ac.apiKey)

	resp, err := ac.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user: status %d", resp.StatusCode)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Placeholder implementations for remaining methods
func (ac *AuthClient) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	return nil, fmt.Errorf("refresh token not implemented in simplified version")
}

func (ac *AuthClient) UpdateUser(ctx context.Context, accessToken string, updates map[string]interface{}) (*User, error) {
	return nil, fmt.Errorf("update user not implemented in simplified version")
}

func (ac *AuthClient) SendPasswordResetEmail(ctx context.Context, email string) error {
	return fmt.Errorf("password reset not implemented in simplified version")
}

func (ac *AuthClient) VerifyOTP(ctx context.Context, phone, token, type_ string) (*AuthResponse, error) {
	return nil, fmt.Errorf("OTP verification not implemented in simplified version")
}

func (ac *AuthClient) SendMagicLinkEmail(ctx context.Context, email string, redirectTo *string) error {
	return fmt.Errorf("magic link not implemented in simplified version")
}

func (ac *AuthClient) SendMobileOTP(ctx context.Context, phone string) error {
	return fmt.Errorf("mobile OTP not implemented in simplified version")
}

func (ac *AuthClient) InviteUser(ctx context.Context, email string, data map[string]interface{}) (*User, error) {
	return nil, fmt.Errorf("invite user not implemented in simplified version")
}

func (ac *AuthClient) DeleteUser(ctx context.Context, userID string) error {
	return fmt.Errorf("delete user not implemented in simplified version")
}

func (ac *AuthClient) ListUsers(ctx context.Context, page, perPage int) ([]User, error) {
	return nil, fmt.Errorf("list users not implemented in simplified version")
}

func (ac *AuthClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	return nil, fmt.Errorf("get user by ID not implemented in simplified version")
}

func (ac *AuthClient) AdminUpdateUser(ctx context.Context, userID string, updates map[string]interface{}) (*User, error) {
	return nil, fmt.Errorf("admin update user not implemented in simplified version")
}

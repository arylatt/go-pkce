package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const (
	// ParamCodeChallenge is the key used to send the challenge value to the server.
	ParamCodeChallenge = "code_challenge"

	// ParamCodeChallengeMethod is the key used to send the challenge method to the server.
	ParamCodeChallengeMethod = "code_challenge_method"

	// ParamCodeVerifier is the key used to send the code verifier to the server.
	ParamCodeVerifier = "code_verifier"

	// MethodS256 is the value to send with ParamCodeChallengeMethod to indicate we are using the
	// S256 encoding method for our challenge.
	MethodS256 = "S256"
)

var (
	// ErrCodeVerifierByteLengthInvalid is returned when calling NewCodeVerifier with a byte length that is outside the permitted value
	// (32-96 bytes).
	ErrCodeVerifierByteLengthInvalid = errors.New("length for new code verifier must be between 32-96 bytes to produce a code verifier string between 43-128 characters")

	// ErrCodeVerifierLengthInvalid is returned when calling CodeChallenge with a verifier that is outside the
	// permitted length (43-128 characters).
	ErrCodeVerifierLengthInvalid = errors.New("code verifier must be between 43-128 characters")
)

// NewCodeVerifier returns a Base64 encoded string of random bytes of the given length.
// Length must be between 32-96, in order to produce a Base64 string between 43-128 characters in length.
// Will return the base64 encoded string, or an error if a byte cannot be generated.
func NewCodeVerifier(length int) (string, error) {
	if length < 32 || length > 96 {
		return "", ErrCodeVerifierByteLengthInvalid
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// CodeChallenge takes a verifier, ensures it is within acceptable length, and generates the challenge to be sent to the server.
// Errors may be returned if the verifier length is invalid, or there is an error during SHA-256 hashing.
func CodeChallenge(verifier string) (string, error) {
	vLen := len(verifier)
	if vLen < 43 || vLen > 128 {
		return "", ErrCodeVerifierLengthInvalid
	}

	hasher := sha256.New()
	_, err := hasher.Write([]byte(verifier))
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyChallengeErr takes a given verifier and challenge and returns if they match.
// Errors may be returned if CodeChallenge(verifier) errors.
func VerifyChallengeErr(verifier, challenge string) (bool, error) {
	challengeCompare, err := CodeChallenge(verifier)
	if err != nil {
		return false, err
	}

	return (challenge == challengeCompare), nil
}

// VerifyChallenge is the same as VerifyChallengeErr, but errors are ignored and a single
// boolean value will be returned.
func VerifyChallenge(verifier, challenge string) bool {
	result, _ := VerifyChallengeErr(verifier, challenge)
	return result
}

package pkce

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCodeVerifier(t *testing.T) {
	tests := []struct {
		inLen  int
		err    error
		outLen int
	}{
		{
			inLen:  31,
			err:    ErrCodeVerifierByteLengthInvalid,
			outLen: 0,
		},
		{
			inLen:  32,
			err:    nil,
			outLen: 43,
		},
		{
			inLen:  96,
			err:    nil,
			outLen: 128,
		},
		{
			inLen:  97,
			err:    ErrCodeVerifierByteLengthInvalid,
			outLen: 0,
		},
	}

	for _, test := range tests {
		str, err := NewCodeVerifier(test.inLen)

		assert.ErrorIs(t, err, test.err)
		assert.Len(t, str, test.outLen)
	}
}

func TestCodeChallenge(t *testing.T) {
	tests := []struct {
		verifier  string
		err       error
		challenge string
	}{
		{
			verifier:  "SOlCo_vVnPOGFAVIZey49j5Sx5Hk_spigKFvFu5LLq",
			err:       ErrCodeVerifierLengthInvalid,
			challenge: "",
		},
		{
			verifier:  "SOlCo_vVnPOGFAVIZey49j5Sx5Hk_spigKFvFu5LLqQ",
			err:       nil,
			challenge: "PERIBnViNq771HEmJfNqXWOzkjnpjwbGXVwNXzIzmA0",
		},
		{
			verifier:  "9lL8JPzd8XbHM4r0irTdovkLPo4hmm2pISA1b9LnVll_Wcrqf2SpzY8r_Umq8OJulgo1un4iVVBb7-gzQdkSCagIifThXSLD03nPAKqppOhvaMX3IWRYZ8mHWiwmVbO8",
			err:       nil,
			challenge: "atYjOhAFKx7k_aXZJAimv5RGiJEm-Vg_l8HfBqe78hs",
		},
		{
			verifier:  "9lL8JPzd8XbHM4r0irTdovkLPo4hmm2pISA1b9LnVll_Wcrqf2SpzY8r_Umq8OJulgo1un4iVVBb7-gzQdkSCagIifThXSLD03nPAKqppOhvaMX3IWRYZ8mHWiwmVbO81",
			err:       ErrCodeVerifierLengthInvalid,
			challenge: "",
		},
	}

	for _, test := range tests {
		str, err := CodeChallenge(test.verifier)

		assert.ErrorIs(t, err, test.err)
		assert.Equal(t, test.challenge, str)
	}
}

func TestVerifyChallenge(t *testing.T) {
	tests := []struct {
		verifier  string
		challenge string
		result    bool
	}{
		{
			verifier:  "SOlCo_vVnPOGFAVIZey49j5Sx5Hk_spigKFvFu5LLq",
			challenge: "",
			result:    false,
		},
		{
			verifier:  "SOlCo_vVnPOGFAVIZey49j5Sx5Hk_spigKFvFu5LLqQ",
			challenge: "PERIBnViNq771HEmJfNqXWOzkjnpjwbGXVwNXzIzmA0",
			result:    true,
		},
		{
			verifier:  "9lL8JPzd8XbHM4r0irTdovkLPo4hmm2pISA1b9LnVll_Wcrqf2SpzY8r_Umq8OJulgo1un4iVVBb7-gzQdkSCagIifThXSLD03nPAKqppOhvaMX3IWRYZ8mHWiwmVbO8",
			challenge: "atYjOhAFKx7k_aXZJAimv5RGiJEm-Vg_l8HfBqe78hs",
			result:    true,
		},
		{
			verifier:  "SOlCo_vVnPOGFAVIZey49j5Sx5Hk_spigKFvFu5LLqQ",
			challenge: "atYjOhAFKx7k_aXZJAimv5RGiJEm-Vg_l8HfBqe78hs",
			result:    false,
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.result, VerifyChallenge(test.verifier, test.challenge))
	}
}

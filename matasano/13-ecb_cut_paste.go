package matasano

import (
	"bytes"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

var (
	uid    = rand.Intn(100000)
	keys13 = []string{"email", "uid", "role"}
)

// CreateAdminProfile creates a profile where the role is "admin"
// It does so by repeated calls to the profilefor() oracle
// Assumptions made: email will be the first param, role will be the last.
// This solves http://cryptopals.com/sets/2/challenges/13
func CreateAdminProfile() []byte {
	frontpad := 16 - len("email=") // assumption that email will be the first parameter
	chosen := newRole(frontpad)
	b := encryptProfile(profilefor(chosen))

	encryptedadmin := make([]byte, 16)
	copy(encryptedadmin, b[16:32])

	blen := len(b)
	for len(b) == blen {
		chosen = "x" + chosen
		b = encryptProfile(profilefor(chosen))
	}

	fakeemail := newEmail(len(chosen) + len("user"))
	b = encryptProfile(profilefor(fakeemail))
	copy(b[len(b)-16:len(b)], encryptedadmin) // assumption that role will be the last parameter

	return b
}

func newRole(frontpad int) string {
	role := []byte("admin")
	role = PadPKCS7(role, 16)
	pad := make([]byte, frontpad)
	pad = append(pad, role...)
	return string(pad)
}

func newEmail(n int) string {
	email := "AChosenEmailOfAppropriateLengthOnADomainWeControl"
	domain := "@nindalf.com"
	return email[0:n-len(domain)] + domain
}

func profilefor(email string) string {
	profile := map[string]string{"email": email, "uid": strconv.Itoa(uid), "role": "user"}
	// return kvencoder(profile)
	return kvencoderBad(profile, keys13)
}

func encryptProfile(profile string) []byte {
	b := []byte(profile)
	b = PadPKCS7(b, 16)
	ecbEnc.CryptBlocks(b, b)
	return b
}

func decryptProfile(profile []byte) map[string]string {
	ecbDec.CryptBlocks(profile, profile)
	profile, _ = StripPKCS7(profile)
	return kvdecoder(string(profile))
}

func kvencoder(params map[string]string) string {
	var b bytes.Buffer
	for k, v := range params {
		if strings.ContainsAny(k, "&=") || strings.ContainsAny(v, "&=") || k == "" || v == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("%s=%s&", k, v))
	}
	result := b.String()
	return result[0 : len(result)-1]
}

func kvencoderBad(params map[string]string, keys []string) string {
	var b bytes.Buffer
	for _, k := range keys {
		v := params[k]
		if strings.ContainsAny(k, "&=") || strings.ContainsAny(v, "&=") || k == "" || v == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("%s=%s&", k, v))
	}
	result := b.String()
	return result[0 : len(result)-1]
}

func kvdecoder(params string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(params, "&")
	for i := range pairs {
		pair := strings.Split(pairs[i], "=")
		result[pair[0]] = pair[1]
	}
	return result
}

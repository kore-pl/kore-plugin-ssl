package certs

import (
	"strings"
	"testing"
	"time"
)

// TestValidateDomain 覆盖域名白名单的合法与非法边界。
func TestValidateDomain(t *testing.T) {
	valid := []string{"example.com", "a-b.example.com", "sub.a-b.co", "x1.y2.z3", "127.0.0.1"}
	for _, domain := range valid {
		if perr := validateDomain(domain); perr != nil {
			t.Fatalf("%q 应合法，得到 %v", domain, perr)
		}
	}
	invalid := []string{
		"", "Example.com", "localhost", ".a.com", "a..com", "-a.com", "a-.com",
		"a.com/../x", "a.com:443", "a b.com", strings.Repeat("a", 254) + ".com",
	}
	for _, domain := range invalid {
		if perr := validateDomain(domain); perr == nil {
			t.Fatalf("%q 应非法", domain)
		}
	}
}

// TestValidateParams 覆盖 days / key_type / extra_sans 的边界。
func TestValidateParams(t *testing.T) {
	if perr := validateDays(0); perr != nil {
		t.Fatal("days=0 表示默认值，应合法")
	}
	if perr := validateDays(1); perr != nil {
		t.Fatal("days=1 应合法")
	}
	for _, days := range []int{-1, 3651} {
		if perr := validateDays(days); perr == nil {
			t.Fatalf("days=%d 应非法", days)
		}
	}
	for _, keyType := range []string{"", "rsa2048", "ecdsa256"} {
		if perr := validateKeyType(keyType); perr != nil {
			t.Fatalf("key_type=%q 应合法", keyType)
		}
	}
	for _, keyType := range []string{"rsa1024", "ecdsa384", "ed25519"} {
		if perr := validateKeyType(keyType); perr == nil {
			t.Fatalf("key_type=%q 应非法", keyType)
		}
	}
	if san, perr := normalizeExtraSAN("127.0.0.1"); perr != nil || san != "127.0.0.1" {
		t.Fatalf("IP 型 extra_san 非法: %q %v", san, perr)
	}
	for _, san := range []string{"", "*.kore.local", "UP.kore.local", "bad/name"} {
		if _, perr := normalizeExtraSAN(san); perr == nil {
			t.Fatalf("extra_san %q 应非法", san)
		}
	}
}

// TestDaysLeft 校验剩余天数取整与过期下界。
func TestDaysLeft(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"exact-365", now.Add(365 * 24 * time.Hour), 365},
		{"just-under-365", now.Add(365*24*time.Hour - time.Minute), 365}, // 向上取整
		{"just-under-364", now.Add(364*24*time.Hour - time.Minute), 364},
		{"30-days", now.Add(30 * 24 * time.Hour), 30},
		{"expired-1h", now.Add(-time.Hour), -1},
		{"expired-2d", now.Add(-48 * time.Hour), -2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := daysLeft(tc.notAfter, now); got != tc.want {
				t.Fatalf("daysLeft=%d，期望 %d", got, tc.want)
			}
		})
	}
}

// TestWildcardCovers 校验通配符只覆盖一级子域。
func TestWildcardCovers(t *testing.T) {
	if !wildcardCovers("*.example.com", "www.example.com") {
		t.Fatal("应覆盖一级子域")
	}
	for _, host := range []string{"a.b.example.com", "example.com", "wwwexample.com"} {
		if wildcardCovers("*.example.com", host) {
			t.Fatalf("不应覆盖 %q", host)
		}
	}
}

package main

import (
	"testing"
	"time"
)

func TestParseSince_GoDurations(t *testing.T) {
	before := time.Now()
	got, err := parseSince("30m")
	if err != nil {
		t.Fatal(err)
	}
	expected := before.Add(-30 * time.Minute)
	if got.Before(expected.Add(-time.Second)) || got.After(expected.Add(time.Second)) {
		t.Errorf("30m: got %v, want ~%v", got, expected)
	}

	before = time.Now()
	got, err = parseSince("4h")
	if err != nil {
		t.Fatal(err)
	}
	expected = before.Add(-4 * time.Hour)
	if got.Before(expected.Add(-time.Second)) || got.After(expected.Add(time.Second)) {
		t.Errorf("4h: got %v, want ~%v", got, expected)
	}
}

func TestParseSince_Days(t *testing.T) {
	before := time.Now()
	got, err := parseSince("7d")
	if err != nil {
		t.Fatal(err)
	}
	expected := before.AddDate(0, 0, -7)
	if got.Before(expected.Add(-time.Second)) || got.After(expected.Add(time.Second)) {
		t.Errorf("7d: got %v, want ~%v", got, expected)
	}
}

func TestParseSince_Months(t *testing.T) {
	before := time.Now()
	got, err := parseSince("3M")
	if err != nil {
		t.Fatal(err)
	}
	expected := before.AddDate(0, -3, 0)
	if got.Before(expected.Add(-time.Second)) || got.After(expected.Add(time.Second)) {
		t.Errorf("3M: got %v, want ~%v", got, expected)
	}
}

func TestParseSince_Years(t *testing.T) {
	before := time.Now()
	got, err := parseSince("1y")
	if err != nil {
		t.Fatal(err)
	}
	expected := before.AddDate(-1, 0, 0)
	if got.Before(expected.Add(-time.Second)) || got.After(expected.Add(time.Second)) {
		t.Errorf("1y: got %v, want ~%v", got, expected)
	}
}

func TestParseSince_Invalid(t *testing.T) {
	cases := []string{"", "abc", "7x", "d", "M", "y"}
	for _, c := range cases {
		_, err := parseSince(c)
		if err == nil {
			t.Errorf("parseSince(%q) should error", c)
		}
	}
}

func TestParseInt(t *testing.T) {
	n, err := parseInt("42")
	if err != nil || n != 42 {
		t.Errorf("parseInt(42) = %d, %v", n, err)
	}

	_, err = parseInt("")
	if err == nil {
		t.Error("parseInt empty should error")
	}

	_, err = parseInt("12x")
	if err == nil {
		t.Error("parseInt non-digit should error")
	}
}

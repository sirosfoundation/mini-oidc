package main

import (
	"testing"
	"time"

	"github.com/sirosfoundation/mini-oidc/internal/users"
)

func testUser() *users.User {
	return &users.User{
		Sub:        "user-1",
		GivenName:  "Ada",
		FamilyName: "Lovelace",
		Name:       "Ada Lovelace",
		Email:      "ada@example.org",
		Organisation: &users.Organisation{
			Name: "Analytical Engines Ltd",
			EUID: "SE.5560001",
		},
		Role:               "signatory",
		RepresentationType: "legal",
		EmployeeID:         "E-42",
	}
}

func TestClaimsForScopesProfile(t *testing.T) {
	claims := claimsForScopes(testUser(), "openid profile")

	if claims["given_name"] != "Ada" || claims["family_name"] != "Lovelace" {
		t.Fatalf("expected profile claims, got %v", claims)
	}
	if _, ok := claims["email"]; ok {
		t.Fatalf("email claim should not be present without email scope, got %v", claims)
	}
	if _, ok := claims["organisation"]; ok {
		t.Fatalf("organisation claim should not be present without organisation scope, got %v", claims)
	}
}

func TestClaimsForScopesEmail(t *testing.T) {
	claims := claimsForScopes(testUser(), "openid email")

	if claims["email"] != "ada@example.org" {
		t.Fatalf("expected email claim, got %v", claims)
	}
}

func TestClaimsForScopesOrganisation(t *testing.T) {
	claims := claimsForScopes(testUser(), "openid organisation")

	org, ok := claims["organisation"].(*users.Organisation)
	if !ok || org.Name != "Analytical Engines Ltd" {
		t.Fatalf("expected organisation claim, got %v", claims["organisation"])
	}
	if claims["role"] != "signatory" {
		t.Fatalf("expected role claim, got %v", claims["role"])
	}
	if claims["representation_type"] != "legal" {
		t.Fatalf("expected representation_type claim, got %v", claims["representation_type"])
	}
	if claims["employee_id"] != "E-42" {
		t.Fatalf("expected employee_id claim, got %v", claims["employee_id"])
	}
}

func TestClaimsForScopesOrganisationOmittedWhenNil(t *testing.T) {
	u := testUser()
	u.Organisation = nil
	u.Role = ""
	u.RepresentationType = ""
	u.EmployeeID = ""

	claims := claimsForScopes(u, "openid organisation")

	if len(claims) != 0 {
		t.Fatalf("expected no claims for empty organisation fields, got %v", claims)
	}
}

func TestClaimsForScopesBackwardsCompat(t *testing.T) {
	claims := claimsForScopes(testUser(), "openid")

	if claims["given_name"] != "Ada" || claims["email"] != "ada@example.org" {
		t.Fatalf("expected backwards-compat claims when no recognized scope, got %v", claims)
	}
}

func ehicUser() *users.User {
	u := testUser()
	u.IssuingAuthority = "Swedish Tax Agency" // profile-scope string form
	u.EHIC = &users.EHIC{
		PersonalAdministrativeNumber: "SE-19900115-0001",
		DocumentNumber:               "SE-EHIC-0000000001",
		IssuingCountry:               "SE",
		IssuingAuthority:             &users.NamedParty{ID: "SE:FK", Name: "Försäkringskassan"},
		AuthenticSource:              &users.NamedParty{ID: "SE:FK", Name: "Försäkringskassan"},
		DateOfIssuance:               "2025-01-15",
		DateOfExpiry:                 "2035-01-15",
		StartingDate:                 "2025-01-15",
		EndingDate:                   "2035-01-15",
	}
	return u
}

func TestClaimsForScopesEHIC(t *testing.T) {
	// apigw requests the credential type as the sole scope
	// (Scopes: []string{session.CredentialType}), so this is the shape that
	// actually reaches the OP in an EHIC issuance.
	claims := claimsForScopes(ehicUser(), "openid ehic")

	if claims["personal_administrative_number"] != "SE-19900115-0001" {
		t.Fatalf("expected personal_administrative_number, got %v", claims)
	}
	if claims["document_number"] != "SE-EHIC-0000000001" {
		t.Fatalf("expected document_number, got %v", claims)
	}
	for _, k := range []string{"date_of_issuance", "date_of_expiry", "starting_date", "ending_date", "issuing_country"} {
		if _, ok := claims[k]; !ok {
			t.Fatalf("expected %s claim, got %v", k, claims)
		}
	}

	// issuing_authority and authentic_source are objects here, not the plain
	// string "profile" releases - the EHIC credential type nests id+name.
	ia, ok := claims["issuing_authority"].(*users.NamedParty)
	if !ok {
		t.Fatalf("expected issuing_authority to be a NamedParty, got %T", claims["issuing_authority"])
	}
	if ia.Name != "Försäkringskassan" {
		t.Fatalf("unexpected issuing_authority: %+v", ia)
	}
	if _, ok := claims["authentic_source"].(*users.NamedParty); !ok {
		t.Fatalf("expected authentic_source to be a NamedParty, got %T", claims["authentic_source"])
	}

	// The backwards-compat fallback must not fire for an ehic-only request; if
	// it did, it would overwrite issuing_authority with the profile string.
	if _, ok := claims["name"]; ok {
		t.Fatalf("ehic scope should not release profile claims, got %v", claims)
	}
}

func TestClaimsForScopesEHICOmittedWhenNil(t *testing.T) {
	claims := claimsForScopes(testUser(), "openid ehic")

	for _, k := range []string{"personal_administrative_number", "document_number", "authentic_source"} {
		if _, ok := claims[k]; ok {
			t.Fatalf("expected no %s for a user without ehic data, got %v", k, claims)
		}
	}
}

func pidUser() *users.User {
	u := testUser()
	u.Birthdate = "1990-01-15"
	u.PlaceOfBirth = "Stockholm"
	u.Nationalities = []string{"SE", "NO"}
	u.IssuingAuthority = "Swedish Tax Agency"
	u.IssuingCountry = "SE"
	return u
}

// apigw requests the credential type as the sole scope
// (Scopes: []string{session.CredentialType}), so a bare "pid_1_8" is the shape
// that actually reaches the OP during issuance - not "profile".
func TestClaimsForScopesPIDARF18(t *testing.T) {
	claims := claimsForScopes(pidUser(), "openid pid_1_8")

	if claims["birthdate"] != "1990-01-15" {
		t.Fatalf("expected birthdate, got %v", claims)
	}
	if claims["place_of_birth"] != "Stockholm" {
		t.Fatalf("expected ARF 1.8 place_of_birth, got %v", claims)
	}
	nats, ok := claims["nationalities"].([]string)
	if !ok || len(nats) != 2 {
		t.Fatalf("expected ARF 1.8 nationalities list, got %T %v", claims["nationalities"], claims["nationalities"])
	}
	if claims["issuing_authority"] != "Swedish Tax Agency" || claims["issuing_country"] != "SE" {
		t.Fatalf("expected issuing authority/country, got %v", claims)
	}

	// ARF 1.5 spellings must NOT appear: a claim under the wrong version's
	// name is not present to disclose, and pollutes the credential besides.
	for _, k := range []string{"birth_place", "nationality", "age_over_18"} {
		if _, ok := claims[k]; ok {
			t.Fatalf("ARF 1.8 must not emit the 1.5 claim %q, got %v", k, claims)
		}
	}

	over, ok := claims["age_equal_or_over"].(map[string]bool)
	if !ok {
		t.Fatalf("expected age_equal_or_over map, got %T", claims["age_equal_or_over"])
	}
	if !over["18"] {
		t.Fatalf("a person born in 1990 is over 18, got %v", over)
	}
	if over["65"] {
		t.Fatalf("a person born in 1990 is not yet 65, got %v", over)
	}
}

func TestClaimsForScopesPIDARF15(t *testing.T) {
	claims := claimsForScopes(pidUser(), "openid pid_1_5")

	if claims["birth_place"] != "Stockholm" {
		t.Fatalf("expected ARF 1.5 birth_place, got %v", claims)
	}
	if claims["nationality"] != "SE" {
		t.Fatalf("expected ARF 1.5 single nationality, got %v", claims["nationality"])
	}
	if claims["age_over_18"] != true || claims["age_over_65"] != false {
		t.Fatalf("expected flat ARF 1.5 age booleans, got %v", claims)
	}

	for _, k := range []string{"place_of_birth", "nationalities", "age_equal_or_over"} {
		if _, ok := claims[k]; ok {
			t.Fatalf("ARF 1.5 must not emit the 1.8 claim %q, got %v", k, claims)
		}
	}
}

// The unversioned "pid" scope follows the current ARF version.
func TestClaimsForScopesPIDUnversionedFollowsARF18(t *testing.T) {
	claims := claimsForScopes(pidUser(), "openid pid")

	if _, ok := claims["age_equal_or_over"]; !ok {
		t.Fatalf("expected \"pid\" to use the ARF 1.8 vocabulary, got %v", claims)
	}
	if _, ok := claims["nationality"]; ok {
		t.Fatalf("expected \"pid\" not to use ARF 1.5 spellings, got %v", claims)
	}
}

// Regression guard for the bug this fixes: these scopes were advertised in
// scopes_supported with no handler, so they fell through to the
// backwards-compat block and released four claims - nowhere near enough to
// build a PID, which made the issuer reject the whole credential request.
func TestClaimsForScopesPIDDoesNotFallThrough(t *testing.T) {
	for _, scope := range []string{"pid", "pid_1_5", "pid_1_8"} {
		claims := claimsForScopes(pidUser(), "openid "+scope)
		if _, ok := claims["name"]; ok {
			t.Fatalf("%s must not fall through to the backwards-compat claims, got %v", scope, claims)
		}
		if _, ok := claims["birthdate"]; !ok {
			t.Fatalf("%s released no birthdate - the fallthrough bug is back: %v", scope, claims)
		}
	}
}

func TestClaimsForScopesPIDOmitsAgeWithoutBirthdate(t *testing.T) {
	u := pidUser()
	u.Birthdate = ""
	claims := claimsForScopes(u, "openid pid_1_8")

	for _, k := range []string{"birthdate", "age_equal_or_over", "age_in_years", "age_birth_year"} {
		if _, ok := claims[k]; ok {
			t.Fatalf("expected no %s for a user without a birthdate, got %v", k, claims)
		}
	}
}

func TestAgeInYearsBirthdayBoundary(t *testing.T) {
	// Day before, day of, and day after an 18th birthday. The day-of case is
	// why this compares month/day rather than day-of-year: 2026 is not a leap
	// year but 2008 was, so the two dates' day-of-year numbers differ.
	for _, tc := range []struct {
		now  string
		want int
	}{
		{"2026-06-19", 17},
		{"2026-06-20", 18},
		{"2026-06-21", 18},
	} {
		now, err := time.Parse("2006-01-02", tc.now)
		if err != nil {
			t.Fatal(err)
		}
		got, _, ok := ageInYears("2008-06-20", now)
		if !ok || got != tc.want {
			t.Fatalf("ageInYears at %s = %d (ok=%v), want %d", tc.now, got, ok, tc.want)
		}
	}
}

func TestAgeInYearsRejectsUnparseableOrFuture(t *testing.T) {
	now, _ := time.Parse("2006-01-02", "2026-06-20")
	for _, bd := range []string{"", "not-a-date", "1990", "2030-01-01"} {
		if _, _, ok := ageInYears(bd, now); ok {
			t.Fatalf("expected ageInYears(%q) to report no derivable age", bd)
		}
	}
}

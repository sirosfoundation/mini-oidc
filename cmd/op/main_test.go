package main

import (
	"testing"

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

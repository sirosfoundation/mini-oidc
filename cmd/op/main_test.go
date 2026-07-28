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

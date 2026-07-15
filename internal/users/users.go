package users

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Address represents a structured postal address (ISA2 Core Location vocabulary).
type Address struct {
	FullAddress        string `yaml:"full_address" json:"full_address,omitempty"`
	Thoroughfare       string `yaml:"thoroughfare" json:"thoroughfare,omitempty"`
	LocatorDesignator  string `yaml:"locator_designator" json:"locator_designator,omitempty"`
	PostCode           string `yaml:"post_code" json:"post_code,omitempty"`
	PostName           string `yaml:"post_name" json:"post_name,omitempty"`
	AdminUnitL1        string `yaml:"admin_unit_l1" json:"admin_unit_l1,omitempty"`
	AdminUnitL2        string `yaml:"admin_unit_l2" json:"admin_unit_l2,omitempty"`
}

// Organisation represents a legal entity that a user is affiliated with.
// Fields align with EUCC, EBWOID, Employee, ContactPerson, and EU PoA credentials.
type Organisation struct {
	Name             string   `yaml:"name" json:"name"`
	EUID             string   `yaml:"euid" json:"euid,omitempty"`
	LEI              string   `yaml:"lei" json:"lei,omitempty"`
	TaxID            string   `yaml:"tax_id" json:"tax_id,omitempty"`
	VatID            string   `yaml:"vat_id" json:"vat_id,omitempty"`
	LegalForm        string   `yaml:"legal_form" json:"legal_form,omitempty"`
	Country          string   `yaml:"country" json:"country,omitempty"`
	RegistrationDate string   `yaml:"registration_date" json:"registration_date,omitempty"`
	Status           string   `yaml:"status" json:"status,omitempty"`
	ActivityCode     string   `yaml:"activity_code" json:"activity_code,omitempty"`
	ActivityDesc     string   `yaml:"activity_description" json:"activity_description,omitempty"`
	RegisteredAddress *Address `yaml:"registered_address" json:"registered_address,omitempty"`
}

type User struct {
	Sub              string   `yaml:"sub" json:"sub"`
	GivenName        string   `yaml:"given_name" json:"given_name,omitempty"`
	FamilyName       string   `yaml:"family_name" json:"family_name,omitempty"`
	Name             string   `yaml:"name" json:"name,omitempty"`
	Email            string   `yaml:"email" json:"email,omitempty"`
	Birthdate        string   `yaml:"birthdate" json:"birthdate,omitempty"`
	PlaceOfBirth     string   `yaml:"place_of_birth" json:"place_of_birth,omitempty"`
	Nationalities    []string `yaml:"nationalities" json:"nationalities,omitempty"`
	IssuingAuthority string   `yaml:"issuing_authority" json:"issuing_authority,omitempty"`
	IssuingCountry   string   `yaml:"issuing_country" json:"issuing_country,omitempty"`

	// Company affiliation fields for representation / legal person scenarios.
	Organisation       *Organisation `yaml:"organisation" json:"organisation,omitempty"`
	Role               string        `yaml:"role" json:"role,omitempty"`
	RepresentationType string        `yaml:"representation_type" json:"representation_type,omitempty"`
	EmployeeID         string        `yaml:"employee_id" json:"employee_id,omitempty"`
}

type UsersFile struct {
	Users []User `yaml:"users"`
}

func Load(path string) (*UsersFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading users file: %w", err)
	}
	var uf UsersFile
	if err := yaml.Unmarshal(data, &uf); err != nil {
		return nil, fmt.Errorf("parsing users file: %w", err)
	}
	if len(uf.Users) == 0 {
		return nil, fmt.Errorf("users file contains no users")
	}
	return &uf, nil
}

func (uf *UsersFile) FindBySub(sub string) *User {
	for i := range uf.Users {
		if uf.Users[i].Sub == sub {
			return &uf.Users[i]
		}
	}
	return nil
}

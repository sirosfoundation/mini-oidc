package users

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

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

package vault

import (
	"context"
	"testing"

	"github.com/evidenceledger/vcdemo/vault/ent"
	"github.com/evidenceledger/vcdemo/vault/x509util"
	"github.com/hesusruiz/vcutils/yaml"
)

func TestVault_CreateCredentialJWTFromMap(t *testing.T) {

	// Open the database in memory
	db, err := ent.Open("sqlite3", "file:test.db?mode=memory&_fk=yes")
	if err != nil {
		t.Errorf("failed opening database")
		return
	}
	// Run the auto migration tool.
	if err := db.Schema.Create(context.Background()); err != nil {
		t.Errorf("failed migration of db, error = %v", err)
		return
	}

	v := &Vault{
		db:   db,
		id:   "HappyPets",
		name: "HappyPets",
	}
	v.InitCredentialTemplates("./templates/*tpl")

	// Parse credential data
	data, err := yaml.ParseYamlFile("./testdata/employee_data.yaml")
	if err != nil {
		t.Errorf("ParseYamlFile error = %v", err)
		return
	}

	// Get the top-level list (the list of credentials)
	creds := data.List("")
	if len(creds) == 0 {
		t.Errorf("No credentials found in file")
		return
	}

	t.Run("Employee Credentials", func(t *testing.T) {

		// Iterate through the list creating each credential which will use its own template
		for _, item := range creds {

			// Cast to a map so it can be passed to CreateCredentialFromMap
			cred, _ := item.(map[string]any)
			_, _, err := v.CreateCredentialJWTFromMap(cred)
			if err != nil {
				t.Errorf("CreateCredentialJWTFromMap error = %v", err)
				return
			}

		}

	})

}

func TestVault_CreateLEARCredentialJWTFromMap(t *testing.T) {

	// Open the database in memory
	db, err := ent.Open("sqlite3", "file:test.db?mode=memory&_fk=yes")
	if err != nil {
		t.Errorf("failed opening database")
		return
	}
	// Run the auto migration tool.
	if err := db.Schema.Create(context.Background()); err != nil {
		t.Errorf("failed migration of db, error = %v", err)
		return
	}

	v := &Vault{
		db:   db,
		id:   "HappyPets",
		name: "HappyPets",
	}
	v.InitCredentialTemplates("./testdata/*tpl")

	// Parse credential data
	data, err := yaml.ParseYamlFile("./testdata/employee_data_lear.yaml")
	if err != nil {
		t.Errorf("ParseYamlFile error = %v", err)
		return
	}

	// Get the top-level list (the list of credentials)
	creds := data.List("")
	if len(creds) == 0 {
		t.Errorf("No credentials found in file")
		return
	}

	elsiName := x509util.ELSIName{
		OrganizationIdentifier: "VATES-12345678",
		CommonName:             "56565656V Beppe Cafiso",
		GivenName:              "Beppe",
		Surname:                "Cafiso",
		EmailAddress:           "beppe@goodair.com",
		SerialNumber:           "56565656V",
		Organization:           "GoodAir",
		Country:                "IT",
	}

	t.Run("Employee Credentials", func(t *testing.T) {

		// Iterate through the list creating each credential which will use its own template
		for _, item := range creds {

			// Cast to a map so it can be passed to CreateCredentialFromMap
			cred, _ := item.(map[string]any)
			_, _, err := v.CreateLEARCredentialJWTFromMap(cred, elsiName)
			if err != nil {
				t.Errorf("CreateLEARCredentialJWTFromMap error = %v", err)
				return
			}

		}

	})

}

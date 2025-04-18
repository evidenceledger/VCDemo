package migrations

import (
	"encoding/json"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/daos"
	m "github.com/pocketbase/pocketbase/migrations"
	"github.com/pocketbase/pocketbase/models/schema"
)

func init() {
	m.Register(func(db dbx.Builder) error {
		dao := daos.New(db);

		collection, err := dao.FindCollectionByNameOrId("8sflyv4gzaox8yp")
		if err != nil {
			return err
		}

		// add
		new_organizationIdentifier := &schema.SchemaField{}
		if err := json.Unmarshal([]byte(`{
			"system": false,
			"id": "mo7aj6wk",
			"name": "organizationIdentifier",
			"type": "text",
			"required": false,
			"presentable": false,
			"unique": false,
			"options": {
				"min": null,
				"max": null,
				"pattern": ""
			}
		}`), new_organizationIdentifier); err != nil {
			return err
		}
		collection.Schema.AddField(new_organizationIdentifier)

		return dao.SaveCollection(collection)
	}, func(db dbx.Builder) error {
		dao := daos.New(db);

		collection, err := dao.FindCollectionByNameOrId("8sflyv4gzaox8yp")
		if err != nil {
			return err
		}

		// remove
		collection.Schema.RemoveField("mo7aj6wk")

		return dao.SaveCollection(collection)
	})
}

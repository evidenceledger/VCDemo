package issuernew

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/skip2/go-qrcode"
	"github.com/valyala/fasttemplate"
)

func (is *IssuerServer) addUserRoutes(e *core.ServeEvent) {

	// Add special normal user routes with a common prefix
	// TODO: document authentication used
	userGroup := e.Router.Group(userApiGroupPrefix)
	userGroup.Use(middleware.CORS())

	userGroup.GET("/startissuancepage/:credid", func(c echo.Context) error {
		return is.startCredentialIssuancePage(c)
	})

	// Retrieve a credential, applying the proper access control depending on the status
	userGroup.GET("/retrievecredential/:credid", func(c echo.Context) error {
		return is.retrieveCredential(c)
	})

	userGroup.POST("/retrievecredential/:credid", func(c echo.Context) error {
		return is.retrieveCredentialPOST(c)
	})

	// Update a credential, applying the proper access control depending on the status
	userGroup.POST("/senddid/:credid", func(c echo.Context) error {
		return is.sendDid(c)
	})

	// Retrieve a credential, applying the proper access control depending on the status
	userGroup.GET("/retrievecredentialpage/:credid", func(c echo.Context) error {
		return is.retrieveCredentialPage(c)
	})

}

func (is *IssuerServer) startCredentialIssuancePage(c echo.Context) error {
	app := is.App

	// Retrieve the credential passed
	id := c.PathParam("credid")
	log.Println("startCredentialIssuance", id)

	credentialRecord, err := app.Dao().FindRecordById("credentials", id)
	if err != nil {
		return err
	}

	// This is the url for Wallet
	wallet_url := is.cfg.String("samedeviceWallet", "https://wallet.mycredential.eu")

	// QRcode for downloading the Wallet
	walletQRcode, err := qrcodeFromUrl(wallet_url)
	if err != nil {
		return err
	}

	const oidprotocol = "openid-credential-offer"
	hostName := strings.TrimPrefix(app.Settings().Meta.AppUrl, "https://")
	prefix := userApiGroupPrefix
	pathRetrieval := prefix + "/retrievecredential/"

	// URL for using from Wallet (cross-device SIOP)
	credURIforQR := oidprotocol + "://" + hostName + pathRetrieval + id

	// Credential QR code for scanning with the Wallet (cross-device SIOP)
	credentialQRcode, err := qrcodeFromUrl(credURIforQR)
	if err != nil {
		return err
	}

	// URL for retrieving the credential in the same-device flow
	credURIsameDevice := "https://" + hostName + pathRetrieval + id
	credentialHref := wallet_url + "/?command=getvc&vcid=" + credURIsameDevice

	html := templateOfferingParse(credentialRecord, walletQRcode, credentialQRcode, credentialHref, credURIsameDevice)

	return c.HTML(http.StatusOK, html)

}

func (is *IssuerServer) retrieveCredential(c echo.Context) error {
	app := is.App

	id := c.PathParam("credid")

	record, err := app.Dao().FindRecordById("credentials", id)
	if err != nil {
		return err
	}

	credential := record.GetString("raw")
	credType := record.GetString("type")
	status := record.GetString("status")

	return c.JSON(http.StatusOK, map[string]any{"credential": credential, "type": credType, "status": status, "id": id})

}

func (is *IssuerServer) retrieveAllCredentials(c echo.Context) error {
	app := is.App

	// Get the info about the holder of the X509 certificate used to authenticate the request
	_, _, err := getX509UserFromHeader(c.Request())
	if err != nil {
		return err
	}

	expr1 := dbx.HashExp{"status": "tobesigned"}
	records, err := app.Dao().FindRecordsByExpr("credentials", expr1)
	if err != nil {
		return err
	}

	return c.JSONPretty(http.StatusOK, records, "  ")

}

type updateCredentialrequest struct {
	DID string `query:"did"`
}

// sendDid receives the did created by the user and updates the credential with it
func (is *IssuerServer) sendDid(c echo.Context) error {
	app := is.App

	// Get the did specified by the user
	var request updateCredentialrequest
	err := c.Bind(&request)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad request")
	}

	// Get the unique id of the credential to be updated
	id := c.PathParam("credid")
	didKey := request.DID
	log.Println("updateCredential", id, didKey)

	// Retrieve the credential from storage
	record, err := app.Dao().FindRecordById("credentials", id)
	if err != nil {
		return err
	}

	// Decode the payload of the JWT, which is the actual credential in JSON
	tokenString := record.GetString("raw")
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token contains an invalid number of segments")
	}

	encoding := base64.RawURLEncoding

	claimsDecoded, err := encoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	// Build the Go struct from the JSON credential
	var learCred LEARCredentialEmployee
	err = json.Unmarshal(claimsDecoded, &learCred)
	if err != nil {
		return err
	}

	// Replace the Mandatee id with the did that the user specified
	learCred.CredentialSubject.Mandate.Mandatee.Id = didKey
	log.Println("Updated Mandate with didKey", didKey)

	// Get the private key from the configured x509 certificate
	privateKey, err := getConfigPrivateKey()
	if err != nil {
		return err
	}

	// Sign the credential with the server certificate
	credential, err := CreateLEARCredentialJWTtoken(learCred, jwt.SigningMethodRS256, privateKey)
	if err != nil {
		return err
	}

	// Update the record in the db
	status := "tobesigned"
	record.Set("raw", credential)
	record.Set("status", status)
	if err := app.Dao().SaveRecord(record); err != nil {
		return err
	}

	credType := record.GetString("type")

	return c.JSON(http.StatusOK, map[string]any{"credential": credential, "type": credType, "status": status, "id": id})

}

type proofClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce,omitempty"`
}

func (o *proofClaims) String() string {
	out, _ := json.MarshalIndent(o, "", "  ")
	return string(out)
}

func (is *IssuerServer) retrieveCredentialPOST(c echo.Context) error {
	type retrieveCredentialPOSTRequest struct {
		Format string `json:"format,omitempty"`
		Proof  struct {
			Proof_type string `json:"proof_type,omitempty"`
			JWT        string `json:"jwt,omitempty"`
		} `json:"proof,omitempty"`
	}

	app := is.App

	id := c.PathParam("credid")

	record, err := app.Dao().FindRecordById("credentials", id)
	if err != nil {
		return err
	}

	var request retrieveCredentialPOSTRequest
	err = c.Bind(&request)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad request")
	}

	proofString := request.Proof.JWT

	var pc = proofClaims{}
	tokenParser := jwt.NewParser()
	proof, _, err := tokenParser.ParseUnverified(proofString, &pc)
	if err != nil {
		return err
	}

	fmt.Print(proof.Claims)

	// Decode the payload of the JWT, which is the actual credential in JSON
	tokenString := record.GetString("raw")
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token contains an invalid number of segments")
	}

	encoding := base64.RawURLEncoding

	claimsDecoded, err := encoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	// Build the Go struct from the JSON credential
	var learCred LEARCredentialEmployee
	err = json.Unmarshal(claimsDecoded, &learCred)
	if err != nil {
		return err
	}

	issuerDID, err := proof.Claims.GetIssuer()
	if err != nil {
		return err
	}

	// Replace the Mandatee id with the did that the user specified
	learCred.CredentialSubject.Mandate.Mandatee.Id = issuerDID
	log.Println("Updated Mandate with didKey", issuerDID)

	// Get the private key from the configured x509 certificate
	privateKey, err := getConfigPrivateKey()
	if err != nil {
		return err
	}

	// Sign the credential with the server certificate
	credential, err := CreateLEARCredentialJWTtoken(learCred, jwt.SigningMethodRS256, privateKey)
	if err != nil {
		return err
	}

	// Update the record in the db
	status := "tobesigned"
	record.Set("raw", credential)
	record.Set("status", status)
	if err := app.Dao().SaveRecord(record); err != nil {
		return err
	}

	credType := record.GetString("type")

	return c.JSON(http.StatusOK, map[string]any{"credential": credential, "type": credType, "status": status, "id": id})

}

func (is *IssuerServer) retrieveCredentialPage(c echo.Context) error {
	app := is.App

	id := c.PathParam("credid")

	credentialRecord, err := app.Dao().FindRecordById("credentials", id)
	if err != nil {
		return err
	}

	// This is the url for Wallet
	wallet_url := is.cfg.String("samedeviceWallet", "https://wallet.mycredential.eu")

	// Create the QR code
	png, err := qrcode.Encode(wallet_url, qrcode.Medium, 256)
	if err != nil {
		return err
	}

	// Convert the image data to a dataURL
	walletQRcode := base64.StdEncoding.EncodeToString(png)
	walletQRcode = "data:image/png;base64," + walletQRcode

	// QR code for cross-device SIOP
	template := "{{protocol}}://{{hostname}}{{prefix}}/retrievecredential/{{id}}"

	t := fasttemplate.New(template, "{{", "}}")
	credURIforQR := t.ExecuteString(map[string]interface{}{
		"protocol": "openid-credential-offer",
		"hostname": app.Settings().Meta.AppUrl,
		"prefix":   userApiGroupPrefix,
		"id":       id,
	})

	// Create the QR
	png, err = qrcode.Encode(credURIforQR, qrcode.Medium, 256)
	if err != nil {
		return err
	}

	t = fasttemplate.New(template, "{{", "}}")
	credURIsameDevice := t.ExecuteString(map[string]interface{}{
		"protocol": c.Scheme(),
		"hostname": app.Settings().Meta.AppUrl,
		"prefix":   userApiGroupPrefix,
		"id":       id,
	})

	credentialHref := wallet_url + "/?command=getvc&vcid=" + credURIsameDevice

	// Convert to a dataURL
	credentialQRcode := base64.StdEncoding.EncodeToString(png)
	credentialQRcode = "data:image/png;base64," + credentialQRcode
	log.Println(credentialQRcode)

	html := templateOfferingParse(credentialRecord, walletQRcode, credentialQRcode, credentialHref, credURIsameDevice)

	return c.HTML(http.StatusOK, html)

}
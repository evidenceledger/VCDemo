import {
  photo_man_default,
  photo_woman_default
} from "../chunks/chunk-EMILS377.js";
import {
  credentialsSave
} from "../chunks/chunk-6CRV2U3L.js";
import "../chunks/chunk-BFXLU5VG.js";
import "../chunks/chunk-66PNVI35.js";

// front/src/pages/LoadAndSaveQRVC.js
var gotoPage = window.MHR.gotoPage;
var goHome = window.MHR.goHome;
var log = window.MHR.log;
var PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
window.MHR.register("LoadAndSaveQRVC", class LoadAndSaveQRVC extends window.MHR.AbstractPage {
  constructor(id) {
    super(id);
  }
  async enter(qrData) {
    let html = this.html;
    if (qrData == null || !qrData.startsWith) {
      console.log("The scanned QR does not contain a valid URL");
      gotoPage("ErrorPage", { "title": "No data received", "msg": "The scanned QR does not contain a valid URL" });
      return;
    }
    if (!qrData.startsWith("https://") && !qrData.startsWith("http://")) {
      console.log("The scanned QR does not contain a valid URL");
      gotoPage("ErrorPage", { "title": "No data received", "msg": "The scanned QR does not contain a valid URL" });
      return;
    }
    if (qrData.includes("/credential-offer?credential_offer_uri=")) {
      var credentialOffer = await getCredentialOffer(qrData);
      var code = credentialOffer["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]["pre-authorized_code"];
      var format = credentialOffer["credentials"][0]["format"];
      var credentialTypes = credentialOffer["credentials"].map((credential) => credential["type"]);
      var issuerAddress = credentialOffer["credential_issuer"];
      var openIdInfo = await getOpenIdConfig(issuerAddress);
      var credentialEndpoint = openIdInfo["credential_endpoint"];
      var tokenEndpoint = openIdInfo["token_endpoint"];
      var authTokenObject = await getAuthToken(tokenEndpoint, code);
      var accessToken = authTokenObject["access_token"];
      var credentialResponse = await getCredentialOIDC4VCI(credentialEndpoint, accessToken, format, credentialTypes);
      console.log("Received the credentials.");
      this.VC = JSON.stringify(credentialResponse["credential"], null, 2);
    } else {
      this.VC = await getVerifiableCredentialLD(qrData);
    }
    const vcRendered = this.vcToHtml(this.VC);
    let theHtml = html`
      <div class="w3-container">
        <div class="w3-card-4 w3-center w3-margin-top w3-padding-bottom">
      
          <div class="w3-container ptb-16">
            <p>${T("You received a Verifiable Credential")}. ${T("You can save it in this device for easy access later, or cancel the operation.")}</p>
          </div>
      
        </div>
      </div>

      ${vcRendered}
      `;
    this.render(theHtml);
  }
  async saveVC() {
    console.log("Save VC " + this.VC);
    var credStruct = {
      "type": "w3cvc",
      "encoded": this.VC,
      "decoded": this.VC
    };
    var saved = await credentialsSave(credStruct);
    if (!saved) {
      return;
    }
    location = window.location.origin + window.location.pathname;
    return;
  }
  cleanReload() {
    location = window.location.origin + window.location.pathname;
    return;
  }
  vcToHtml(vcencoded) {
    let html = this.html;
    const vc = JSON.parse(vcencoded);
    const vcs = vc.credentialSubject;
    const pos = vcs.position;
    var avatar = photo_man_default;
    if (vcs.gender == "f") {
      avatar = photo_woman_default;
    }
    const div = html`<div class="w3-half w3-container w3-margin-bottom">
        <div class="w3-card-4">
            <div class="w3-padding-left w3-margin-bottom color-primary">
                <h4>Employee</h4>
            </div>

            <div class="w3-container">
                <img src=${avatar} alt="Avatar" class="w3-left w3-circle w3-margin-right" style="width:60px">
                <p class="w3-large">${vcs.name}</p>
                <hr>
            <div class="w3-row-padding">

            <div class=" w3-container">
                <p class="w3-margin-bottom5">${pos.department}</p>
                <p class="w3-margin-bottom5">${pos.secretariat}</p>
                <p class="w3-margin-bottom5">${pos.directorate}</p>
                <p class="w3-margin-bottom5">${pos.subdirectorate}</p>
                <p class="w3-margin-bottom5">${pos.service}</p>
                <p class="w3-margin-bottom5">${pos.section}</p>
            </div>

            <div class="w3-padding-16">
              <btn-primary @click=${() => this.cleanReload()}>${T("Cancel")}</btn-primary>
              <btn-primary @click=${() => this.saveVC()}>${T("Save")}</btn-primary>
            </div>

        </div>
    </div>`;
    return div;
  }
});
async function getCredentialOIDC4VCI(credentialEndpoint, accessToken, format, credential_type) {
  try {
    var credentialReq = {
      format,
      types: credential_type
    };
    console.log("Body " + JSON.stringify(credentialReq));
    let response = await fetch(credentialEndpoint, {
      method: "POST",
      cache: "no-cache",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + accessToken
      },
      body: JSON.stringify(credentialReq),
      mode: "cors"
    });
    if (response.ok) {
      var credentialBody = await response.json();
    } else {
      if (response.status == 403) {
        alert.apply("error 403");
        window.MHR.goHome();
        return "Error 403";
      }
      var error = await response.text();
      log.error(error);
      window.MHR.goHome();
      alert(error);
      return null;
    }
  } catch (error2) {
    log.error(error2);
    alert(error2);
    return null;
  }
  console.log(credentialBody);
  return credentialBody;
}
async function getAuthToken(tokenEndpoint, preAuthCode) {
  try {
    var formAttributes = {
      "grant_type": PRE_AUTHORIZED_CODE_GRANT_TYPE,
      "code": preAuthCode
    };
    var formBody = [];
    for (var property in formAttributes) {
      var encodedKey = encodeURIComponent(property);
      var encodedValue = encodeURIComponent(formAttributes[property]);
      formBody.push(encodedKey + "=" + encodedValue);
    }
    formBody = formBody.join("&");
    console.log("The body: " + formBody);
    let response = await fetch(tokenEndpoint, {
      method: "POST",
      cache: "no-cache",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: formBody,
      mode: "cors"
    });
    if (response.ok) {
      var tokenBody = await response.json();
    } else {
      if (response.status == 403) {
        alert.apply("error 403");
        window.MHR.goHome();
        return "Error 403";
      }
      var error = await response.text();
      log.error(error);
      window.MHR.goHome();
      alert(error);
      return null;
    }
  } catch (error2) {
    log.error(error2);
    alert(error2);
    return null;
  }
  console.log(tokenBody);
  return tokenBody;
}
async function getOpenIdConfig(issuerAddress) {
  try {
    console.log("Get: " + issuerAddress);
    let response = await fetch(issuerAddress + "/.well-known/openid-configuration", {
      cache: "no-cache",
      mode: "cors"
    });
    if (response.ok) {
      var openIdInfo = await response.json();
    } else {
      if (response.status == 403) {
        alert.apply("error 403");
        window.MHR.goHome();
        return "Error 403";
      }
      var error = await response.text();
      log.error(error);
      window.MHR.goHome();
      alert(error);
      return null;
    }
  } catch (error2) {
    log.error(error2);
    alert(error2);
    return null;
  }
  console.log(openIdInfo);
  return openIdInfo;
}
async function getVerifiableCredentialLD(backEndpoint) {
  try {
    let response = await fetch(backEndpoint, {
      mode: "cors"
    });
    if (response.ok) {
      var vc = await response.text();
    } else {
      if (response.status == 403) {
        alert.apply("error 403");
        window.MHR.goHome();
        return "Error 403";
      }
      var error = await response.text();
      log.error(error);
      window.MHR.goHome();
      alert(error);
      return null;
    }
  } catch (error2) {
    log.error(error2);
    alert(error2);
    return null;
  }
  console.log(vc);
  return vc;
}
async function getCredentialOffer(url) {
  try {
    const urlParams = new URL(url).searchParams;
    const credentialOfferURI = decodeURIComponent(urlParams.get("credential_offer_uri"));
    console.log("Get: " + credentialOfferURI);
    let response = await fetch(credentialOfferURI, {
      cache: "no-cache",
      mode: "cors"
    });
    if (response.ok) {
      const credentialOffer = await response.json();
      console.log(credentialOffer);
      return credentialOffer;
    } else {
      if (response.status === 403) {
        alert.apply("error 403");
        window.MHR.goHome();
        return "Error 403";
      }
      var error = await response.text();
      log.error(error);
      window.MHR.goHome();
      alert(error);
      return null;
    }
  } catch (error2) {
    log.error(error2);
    alert(error2);
    return null;
  }
}

import {
  photo_man_default,
  photo_woman_default
} from "../chunks/chunk-EMILS377.js";
import "../chunks/chunk-66PNVI35.js";

// front/node_modules/js-base64/base64.mjs
var version = "3.7.5";
var VERSION = version;
var _hasatob = typeof atob === "function";
var _hasbtoa = typeof btoa === "function";
var _hasBuffer = typeof Buffer === "function";
var _TD = typeof TextDecoder === "function" ? new TextDecoder() : void 0;
var _TE = typeof TextEncoder === "function" ? new TextEncoder() : void 0;
var b64ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
var b64chs = Array.prototype.slice.call(b64ch);
var b64tab = ((a) => {
  let tab = {};
  a.forEach((c, i) => tab[c] = i);
  return tab;
})(b64chs);
var b64re = /^(?:[A-Za-z\d+\/]{4})*?(?:[A-Za-z\d+\/]{2}(?:==)?|[A-Za-z\d+\/]{3}=?)?$/;
var _fromCC = String.fromCharCode.bind(String);
var _U8Afrom = typeof Uint8Array.from === "function" ? Uint8Array.from.bind(Uint8Array) : (it) => new Uint8Array(Array.prototype.slice.call(it, 0));
var _mkUriSafe = (src) => src.replace(/=/g, "").replace(/[+\/]/g, (m0) => m0 == "+" ? "-" : "_");
var _tidyB64 = (s) => s.replace(/[^A-Za-z0-9\+\/]/g, "");
var btoaPolyfill = (bin) => {
  let u32, c0, c1, c2, asc = "";
  const pad = bin.length % 3;
  for (let i = 0; i < bin.length; ) {
    if ((c0 = bin.charCodeAt(i++)) > 255 || (c1 = bin.charCodeAt(i++)) > 255 || (c2 = bin.charCodeAt(i++)) > 255)
      throw new TypeError("invalid character found");
    u32 = c0 << 16 | c1 << 8 | c2;
    asc += b64chs[u32 >> 18 & 63] + b64chs[u32 >> 12 & 63] + b64chs[u32 >> 6 & 63] + b64chs[u32 & 63];
  }
  return pad ? asc.slice(0, pad - 3) + "===".substring(pad) : asc;
};
var _btoa = _hasbtoa ? (bin) => btoa(bin) : _hasBuffer ? (bin) => Buffer.from(bin, "binary").toString("base64") : btoaPolyfill;
var _fromUint8Array = _hasBuffer ? (u8a) => Buffer.from(u8a).toString("base64") : (u8a) => {
  const maxargs = 4096;
  let strs = [];
  for (let i = 0, l = u8a.length; i < l; i += maxargs) {
    strs.push(_fromCC.apply(null, u8a.subarray(i, i + maxargs)));
  }
  return _btoa(strs.join(""));
};
var fromUint8Array = (u8a, urlsafe = false) => urlsafe ? _mkUriSafe(_fromUint8Array(u8a)) : _fromUint8Array(u8a);
var cb_utob = (c) => {
  if (c.length < 2) {
    var cc = c.charCodeAt(0);
    return cc < 128 ? c : cc < 2048 ? _fromCC(192 | cc >>> 6) + _fromCC(128 | cc & 63) : _fromCC(224 | cc >>> 12 & 15) + _fromCC(128 | cc >>> 6 & 63) + _fromCC(128 | cc & 63);
  } else {
    var cc = 65536 + (c.charCodeAt(0) - 55296) * 1024 + (c.charCodeAt(1) - 56320);
    return _fromCC(240 | cc >>> 18 & 7) + _fromCC(128 | cc >>> 12 & 63) + _fromCC(128 | cc >>> 6 & 63) + _fromCC(128 | cc & 63);
  }
};
var re_utob = /[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g;
var utob = (u) => u.replace(re_utob, cb_utob);
var _encode = _hasBuffer ? (s) => Buffer.from(s, "utf8").toString("base64") : _TE ? (s) => _fromUint8Array(_TE.encode(s)) : (s) => _btoa(utob(s));
var encode = (src, urlsafe = false) => urlsafe ? _mkUriSafe(_encode(src)) : _encode(src);
var encodeURI = (src) => encode(src, true);
var re_btou = /[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/g;
var cb_btou = (cccc) => {
  switch (cccc.length) {
    case 4:
      var cp = (7 & cccc.charCodeAt(0)) << 18 | (63 & cccc.charCodeAt(1)) << 12 | (63 & cccc.charCodeAt(2)) << 6 | 63 & cccc.charCodeAt(3), offset = cp - 65536;
      return _fromCC((offset >>> 10) + 55296) + _fromCC((offset & 1023) + 56320);
    case 3:
      return _fromCC((15 & cccc.charCodeAt(0)) << 12 | (63 & cccc.charCodeAt(1)) << 6 | 63 & cccc.charCodeAt(2));
    default:
      return _fromCC((31 & cccc.charCodeAt(0)) << 6 | 63 & cccc.charCodeAt(1));
  }
};
var btou = (b) => b.replace(re_btou, cb_btou);
var atobPolyfill = (asc) => {
  asc = asc.replace(/\s+/g, "");
  if (!b64re.test(asc))
    throw new TypeError("malformed base64.");
  asc += "==".slice(2 - (asc.length & 3));
  let u24, bin = "", r1, r2;
  for (let i = 0; i < asc.length; ) {
    u24 = b64tab[asc.charAt(i++)] << 18 | b64tab[asc.charAt(i++)] << 12 | (r1 = b64tab[asc.charAt(i++)]) << 6 | (r2 = b64tab[asc.charAt(i++)]);
    bin += r1 === 64 ? _fromCC(u24 >> 16 & 255) : r2 === 64 ? _fromCC(u24 >> 16 & 255, u24 >> 8 & 255) : _fromCC(u24 >> 16 & 255, u24 >> 8 & 255, u24 & 255);
  }
  return bin;
};
var _atob = _hasatob ? (asc) => atob(_tidyB64(asc)) : _hasBuffer ? (asc) => Buffer.from(asc, "base64").toString("binary") : atobPolyfill;
var _toUint8Array = _hasBuffer ? (a) => _U8Afrom(Buffer.from(a, "base64")) : (a) => _U8Afrom(_atob(a).split("").map((c) => c.charCodeAt(0)));
var toUint8Array = (a) => _toUint8Array(_unURI(a));
var _decode = _hasBuffer ? (a) => Buffer.from(a, "base64").toString("utf8") : _TD ? (a) => _TD.decode(_toUint8Array(a)) : (a) => btou(_atob(a));
var _unURI = (a) => _tidyB64(a.replace(/[-_]/g, (m0) => m0 == "-" ? "+" : "/"));
var decode = (src) => _decode(_unURI(src));
var isValid = (src) => {
  if (typeof src !== "string")
    return false;
  const s = src.replace(/\s+/g, "").replace(/={0,2}$/, "");
  return !/[^\s0-9a-zA-Z\+/]/.test(s) || !/[^\s0-9a-zA-Z\-_]/.test(s);
};
var _noEnum = (v) => {
  return {
    value: v,
    enumerable: false,
    writable: true,
    configurable: true
  };
};
var extendString = function() {
  const _add = (name, body) => Object.defineProperty(String.prototype, name, _noEnum(body));
  _add("fromBase64", function() {
    return decode(this);
  });
  _add("toBase64", function(urlsafe) {
    return encode(this, urlsafe);
  });
  _add("toBase64URI", function() {
    return encode(this, true);
  });
  _add("toBase64URL", function() {
    return encode(this, true);
  });
  _add("toUint8Array", function() {
    return toUint8Array(this);
  });
};
var extendUint8Array = function() {
  const _add = (name, body) => Object.defineProperty(Uint8Array.prototype, name, _noEnum(body));
  _add("toBase64", function(urlsafe) {
    return fromUint8Array(this, urlsafe);
  });
  _add("toBase64URI", function() {
    return fromUint8Array(this, true);
  });
  _add("toBase64URL", function() {
    return fromUint8Array(this, true);
  });
};
var extendBuiltins = () => {
  extendString();
  extendUint8Array();
};
var gBase64 = {
  version,
  VERSION,
  atob: _atob,
  atobPolyfill,
  btoa: _btoa,
  btoaPolyfill,
  fromBase64: decode,
  toBase64: encode,
  encode,
  encodeURI,
  encodeURL: encodeURI,
  utob,
  btou,
  decode,
  isValid,
  fromUint8Array,
  toUint8Array,
  extendString,
  extendUint8Array,
  extendBuiltins
};

// front/src/pages/SIOPSelectCredential.js
var gotoPage = window.MHR.gotoPage;
var goHome = window.MHR.goHome;
var storage = window.MHR.storage;
var log = window.MHR.log;
var html = window.MHR.html;
window.MHR.register("SIOPSelectCredential", class SIOPSelectCredential extends window.MHR.AbstractPage {
  WebAuthnSupported = false;
  PlatformAuthenticatorSupported = false;
  constructor(id) {
    super(id);
  }
  async enter(qrData) {
    let html2 = this.html;
    log.log("Inside SIOPSelectCredential:", qrData);
    if (qrData == null) {
      log.error("No URL has been specified");
      gotoPage("ErrorPage", {
        title: "Error",
        msg: "No URL has been specified"
      });
      return;
    }
    if (window.PublicKeyCredential) {
      this.WebAuthnSupported = true;
      let available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (available) {
        this.PlatformAuthenticatorSupported = true;
      }
    }
    qrData = qrData.replace("openid://?", "");
    var params = new URLSearchParams(qrData);
    var redirect_uri = params.get("redirect_uri");
    var state = params.get("state");
    var scope = params.get("scope");
    log.log("state", state);
    log.log("redirect_uri", redirect_uri);
    log.log("scope", scope);
    var credentialType = "Employee";
    var rpURL = new URL(redirect_uri);
    var rpDomain = rpURL.hostname;
    var credStructs = await storage.credentialsGetAllRecent();
    if (!credStructs) {
      let theHtml2 = html2`
                <div class="w3-panel w3-margin w3-card w3-center w3-round color-error">
                <p>You do not have a Verifiable Credential.</p>
                <p>Please go to an Issuer to obtain one.</p>
                </div>
            `;
      this.render(theHtml2);
      return;
    }
    var credentials = [];
    for (const cc of credStructs) {
      const vc = JSON.parse(cc.encoded);
      const vctype = vc.type;
      if (vctype.includes(scope)) {
        console.log("found", cc.encoded);
        credentials.push(vc);
        break;
      }
    }
    if (credentials.length == 0) {
      var msg = html2`
                <p><b>${rpDomain}</b> has requested a Verifiable Credential of type ${credentialType} to perform authentication,
                but you do not have any credential of that type.</p>
                <p>Please go to an Issuer to obtain one.</p>
            `;
      const errPanel = window.MHR.ErrorPanel(T("Error"), msg);
      this.render(errPanel);
      return;
    }
    let theHtml = html2`
        <p></p>
        <div class="w3-row">
            <div class=" w3-container">
                <p>
                    <b>${rpDomain}</b> has requested a Verifiable Credential of type ${credentialType} to perform authentication.
                </p>
                <p>
                    If you want to send the credential, click the button "Send Credential".
                </p>
            </div>
            
            ${vcToHtml(credentials[0], redirect_uri, state, this.WebAuthnSupported)}

        </div>
        `;
    this.render(theHtml);
  }
});
async function sendCredential(backEndpoint, credentials, state, authSupported) {
  log.log("sending POST to:", backEndpoint + "?state=" + state);
  var ps = {
    id: "Placeholder - not yet evaluated.",
    definition_id: "Example definition."
  };
  log.log("The credentials: " + credentials);
  var vpToken = {
    context: ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiablePresentation"],
    verifiableCredential: credentials,
    // currently unverified
    holder: "did:my:wallet"
  };
  log.log("The encoded credential ", gBase64.encodeURI(JSON.stringify(vpToken)));
  var formAttributes = {
    "vp_token": gBase64.encodeURI(JSON.stringify(vpToken)),
    "presentation_submission": gBase64.encodeURI(JSON.stringify(ps))
  };
  var formBody = JSON.stringify(formAttributes);
  log.log("The body: " + formBody);
  try {
    let response = await fetch(backEndpoint + "?state=" + state, {
      method: "POST",
      mode: "no-cors",
      cache: "no-cache",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: formBody
    });
    if (!authSupported) {
      gotoPage("ErrorPage", {
        title: "Error",
        msg: "Authenticator not supported in this device"
      });
      return;
    }
    if (response.status == 404) {
      var email = await response.text();
      log.log("credential sent, registering user", email);
      let error = await registerUser(email, state);
      if (error == null) {
        log.log("Authenticator credential sent successfully to server");
        gotoPage("MessagePage", {
          title: "Credential sent",
          msg: "Registration successful"
        });
      } else {
        log.error(error);
        gotoPage("ErrorPage", {
          title: "Error",
          msg: "Error sending the credential"
        });
      }
      return;
    }
    if (response.status == 200) {
      var email = await response.text();
      log.log("credential sent, authenticating user", email);
      let error = await loginUser(email, state);
      if (error) {
        log.error(error);
        gotoPage("ErrorPage", {
          title: "Error",
          msg: "Error sending the credential"
        });
      } else {
        log.log("Authenticator credential sent successfully to server");
        gotoPage("MessagePage", {
          title: "Credential sent",
          msg: "Authentication successful"
        });
      }
      return;
    }
    log.error("error sending credential", response.status);
    gotoPage("ErrorPage", {
      title: "Error",
      msg: "Error sending the credential"
    });
    return;
  } catch (error) {
    log.error(error);
    gotoPage("ErrorPage", {
      title: "Error",
      msg: "Error sending the credential"
    });
    return;
  }
}
var apiPrefix = "/webauthn";
async function registerUser(username, state) {
  try {
    var response = await fetch(apiPrefix + "/register/begin/" + username + "?state=" + state, { credentials: "include" });
    if (!response.ok) {
      var errorText = await response.text();
      log.log(errorText);
      return "error";
    }
    var responseJSON = await response.json();
    var credentialCreationOptions = responseJSON.options;
    var session = responseJSON.session;
    log.log("Received CredentialCreationOptions", credentialCreationOptions);
    log.log("Session:", session);
    credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
    credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
    if (credentialCreationOptions.publicKey.excludeCredentials) {
      for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
        credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
      }
    }
    log.log("creating new Authenticator credential");
    try {
      var credential = await navigator.credentials.create({
        publicKey: credentialCreationOptions.publicKey
      });
    } catch (error) {
      log.error(error);
      return error;
    }
    log.log("Authenticator created Credential", credential);
    let attestationObject = credential.response.attestationObject;
    let clientDataJSON = credential.response.clientDataJSON;
    let rawId = credential.rawId;
    var data = {
      id: credential.id,
      rawId: bufferEncode(rawId),
      type: credential.type,
      response: {
        attestationObject: bufferEncode(attestationObject),
        clientDataJSON: bufferEncode(clientDataJSON)
      }
    };
    var wholeData = {
      response: data,
      session
    };
    log.log("sending Authenticator credential to server");
    var response = await fetch(apiPrefix + "/register/finish/" + username + "?state=" + state, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "session_id": session
      },
      credentials: "include",
      mode: "cors",
      body: JSON.stringify(wholeData)
      // body data type must match "Content-Type" header
    });
    if (!response.ok) {
      var errorText = await response.text();
      log.log(errorText);
      return "error";
    }
    log.log("Authenticator credential sent successfully to server");
    return;
  } catch (error) {
    log.error(error);
    return error;
  }
}
async function loginUser(username, state) {
  try {
    var response = await fetch(apiPrefix + "/login/begin/" + username + "?state=" + state, { credentials: "include" });
    if (!response.ok) {
      log.error("error requesting CredentialRequestOptions", response.status);
      return "error";
    }
    var responseJSON = await response.json();
    var credentialRequestOptions = responseJSON.options;
    var session = responseJSON.session;
    log.log("Received CredentialRequestOptions", credentialRequestOptions);
    credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
    credentialRequestOptions.publicKey.allowCredentials.forEach(function(listItem) {
      listItem.id = bufferDecode(listItem.id);
    });
    try {
      var assertion = await navigator.credentials.get({
        publicKey: credentialRequestOptions.publicKey
      });
      if (assertion == null) {
        log.error("null assertion received from authenticator device");
        return "error";
      }
    } catch (error) {
      log.error(error);
      return error;
    }
    log.log("Authenticator created Assertion", assertion);
    let authData = assertion.response.authenticatorData;
    let clientDataJSON = assertion.response.clientDataJSON;
    let rawId = assertion.rawId;
    let sig = assertion.response.signature;
    let userHandle = assertion.response.userHandle;
    var data = {
      id: assertion.id,
      rawId: bufferEncode(rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufferEncode(authData),
        clientDataJSON: bufferEncode(clientDataJSON),
        signature: bufferEncode(sig),
        userHandle: bufferEncode(userHandle)
      }
    };
    var wholeData = {
      response: data,
      session
    };
    try {
      var response = await fetch(apiPrefix + "/login/finish/" + username + "?state=" + state, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "session_id": session
        },
        credentials: "include",
        mode: "cors",
        body: JSON.stringify(wholeData)
      });
      if (!response.ok) {
        var errorText = await response.text();
        log.log(errorText);
        return "error";
      }
      return;
    } catch (error) {
      log.error(error);
      return error;
    }
  } catch (error) {
    log.error(error);
    return error;
  }
}
function bufferDecode(value) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  ;
}
function vcToHtml(vc, redirect_uri, state, webAuthnSupported) {
  var credentials = [vc];
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
              <btn-primary @click=${() => window.MHR.cleanReload()}>${T("Cancel")}</btn-primary>
              <btn-primary @click=${() => sendCredential(redirect_uri, credentials, state, webAuthnSupported)}>${T("Send Credential")}</btn-primary>
            </div>

        </div>
    </div>`;
  return div;
}

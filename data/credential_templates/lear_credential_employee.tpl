{{define "LEARCredentialEmployee" -}}
{{ $now := now | unixEpoch -}}
{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.evidenceledger.eu/2022/credentials/employee/v1"
    ],
    "id": "{{.jti}}",
    "type": ["VerifiableCredential", "LEARCredentialEmployee"],
    "issuer": {
        "id": "{{.issuerDID}}"
    },
    "issuanceDate": "{{ $now }}",
    "validFrom": "{{ $now }}",
    "expirationDate": "{{ add $now 10000 }}",
    "credentialSubject": {{toPrettyJson .claims}}
}
{{end}}

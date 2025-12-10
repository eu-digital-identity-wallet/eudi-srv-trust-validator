# EUDI Trust Validator Service

**Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Table of contents

* [Overview](#overview)
* [Disclaimer](#disclaimer)
* [How to build and run](#how-to-build-and-run)
* [Endpoints](#endpoints)
* [Configuration](#configuration)
* [How to contribute](#how-to-contribute)
* [License](#license)

## Overview

Simple Kotlin/Spring Boot WebFlux service to check whether an X.509 certificate chain (x5c) is trusted for a given service type.

What it does
- Exposes a single endpoint: /trust
- Validates an incoming x5c chain against configured trust sources (List of Trusted Lists and/or keystores)

Notes
- x5c items are Base64 DER format.

Service type mapping
- PIDProvider  
- QEAAProvider  
- PubEAAProvider  
- WalletProvider  

## Disclaimer

The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported

## How to build and run

To start the service locally you can execute 
```bash
./gradlew bootRun
```
To build a local docker image of the service execute
```bash
./gradlew bootBuildImage
```

To start the docker compose environment
```bash
# From project root directory 
cd docker
docker-compose up -d
```
To stop the docker compose environment
```bash
# From project root directory 
cd docker
docker-compose down
```

## Endpoints

### Check a X509 certificate chain if trusted

- _Method_: POST
- _URL_: http://localhost:8080/trust
- _Actor_: [Trust](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/TrustApi.kt)

An endpoint to validates an incoming x5c chain against configured trust sources (List of Trusted Lists and/or keystores). Payload of this request is a json object with the following acceptable attributes:
- `x5c`: X509 certificates in Base64 (DER format).
- `serviceType`: Provider type that X5C chain belongs to. Allowed values: `PIDProvider`, `QEAAProvider`, `PubEAAProvider`, `WalletProvider`.

**Usage:**

```bash
curl -X POST -H "Content-type: application/json" -d '{
  "x5c": [
    "MIIC6zCCApGgAwIBAgIUbX8nbYSLRvy10mKN+hfCVr/8cBcwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI1MDQxMDE0MjU0MFoXDTI2MDcwNDE0MjUzOVowUjEUMBIGA1UEAwwLUElEIERTIC0gMDMxLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrxZ13wLj/nUuGebYRmPO0q7pRk1x1SjrqLTvtQFpQcy9TwFCcgie/BBC2j/KpLcCr+oj4tyZAofmvHdaTExbBo4IBOTCCATUwHwYDVR0jBBgwFoAUYseURyi9D6IWIKeawkmURPEB08cwJwYDVR0RBCAwHoIcZGV2Lmlzc3Vlci1iYWNrZW5kLmV1ZGl3LmRldjAWBgNVHSUBAf8EDDAKBggrgQICAAABAjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAyLmNybDAdBgNVHQ4EFgQUcs3KyqizHgtXRe32n6JBJHAfaLYwDgYDVR0PAQH/BAQDAgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDSAAwRQIgTVZnchD+Qjq53Xs0oc07y3zG6kAXFkJ+ZKzlVG22sC8CIQDtDMQq0Qm/fQ5orrjRT4XB+0Jb6xFPxX9QkVRaMy/IiA=="
  ],
  "serviceType": "PIDProvider"
}' 'http://localhost:8080/trust'
```

**Returns:**
```json
{
  "trusted": "true"
}
```

## Configuration

The Verifier Endpoint application can be configured using the following *environment* variables:

Variable: `SERVER_PORT`  
Description: Port for the HTTP listener of the Verifier Endpoint application  
Default value: `8080`

Variable: `CORS_ORIGINS`  
Description: Comma separated list of allowed Origins for cross-origin requests  
Default value: `*`

Variable: `CORS_ORIGINPATTERNS`  
Description: Comma separated list of patterns used for more fine grained matching of allowed Origins for cross-origin requests  
Default value: `*`

Variable: `CORS_METHODS`  
Description: Comma separated list of HTTP methods allowed for cross-origin requests  
Default value: `*`

Variable: `CORS_HEADERS`  
Description: Comma separated list of allowed and exposed HTTP Headers for cross-origin requests  
Default value: `*`

Variable: `CORS_CREDENTIALS`  
Description: Whether credentials (i.e. Cookies or Authorization Header) are allowed for cross-origin requests
Default value: `false`

Variable: `CORS_MAXAGE`  
Description: Time in seconds of how long pre-flight request responses can be cached by clients  
Default value: `3600`

### Configuring trust sources

The verifier supports the configuration of multiple trust sources, that will be used to trust the issuers of presented credentials.  
Each trust source is associated with a regex pattern, that will be used to match the trust source to an issuer, based on a credential's docType/vct.
Each trust source can be configured with a List of Trusted Lists, a Keystore or both.
The trust sources are configured using the environment variable `TRUSTSOURCES` and are indexed starting from `0`. You can define multiple trust sources by incrementing the index (e.g., VERIFIER_TRUSTSOURCES_0_*, VERIFIER_TRUSTSOURCES_1_*, etc.)

Variable: `TRUSTSOURCES_0_PROVIDERTYPE`  
Description: The provider type of the trust source.  
Default value: `PIDProvider`  
Example: `PIDProvider`, `QEAAProvider`, `PubEAAProvider`, `WalletProvider`  

Variable: `TRUSTSOURCES_0_LOTL_LOCATION`  
Description: If present, the URL of the List of Trusted Lists from which to load the X509 Certificates for this trust source  

Variable: `TRUSTSOURCES_0_LOTL_REFRESHINTERVAL`  
Description: If present, a cron expression with the refresh interval of the List of Trusted Lists in seconds. If not present, the default value is `0 0 * * * * ` (every hour)  
Example: `0 0 */4 * * *`  

Variable: `TRUSTSOURCES_0_LOTL_SERVICETYPEFILTER`  
Description: If present, the service type filter to be used when loading the List of Trusted Lists. If not present, all service types are loaded. Valid values are `PIDProvider`, `QEEAProvider` and `PubEAAProvider`.  
Example: `PIDProvider`  

Variable: `TRUSTSOURCES_0_LOTL_KEYSTORE_PATH`  
Description: If present, the URL of the Keystore which contains the public key that was used to sign the List of Trusted Lists  
Examples: `classpath:lotl-key.jks`, `file:///lotl-key.jks`  

Variable: `TRUSTSOURCES_0_LOTL_KEYSTORE_TYPE`  
Description: Type of the Keystore which contains the public key that was used to sign the List of Trusted Lists  
Examples: `jks`, `pkcs12`  

Variable: `TRUSTSOURCES_0_LOTL_KEYSTORE_PASSWORD`  
Description: If present and non-blank, the password of the Keystore which contains the public key that was used to sign the List of Trusted Lists  

Variable: `TRUSTSOURCES_0_KEYSTORE_PATH`  
Description: If present, the URL of the Keystore from which to load the X509 Certificates for this trust source   
Examples: `classpath:trusted-issuers.jks`, `file:///trusted-issuers.jks`  

Variable: `TRUSTSOURCES_0_KEYSTORE_TYPE`  
Description: Type of the Keystore from which to load the X509 Certificates for this trust source  
Examples: `jks`, `pkcs12`  

Variable: `TRUSTSOURCES_0_KEYSTORE_PASSWORD`  
Description: If present and non-blank, the password of the Keystore from which to load the X509 Certificates for this trust source  

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone  
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

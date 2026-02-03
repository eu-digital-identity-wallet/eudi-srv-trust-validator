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

Trust Validator Service is a web application used to check whether an X.509 certificate chain is trusted or not. The implementation is
based on [eudi-lib-kmp-etsi-1196x2](https://github.com/eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2).

Currently, the following sources for Trust Anchors are supported:

1. Lists of Trusted Lists (LoTLs), based on [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf)
2. Java KeyStores

## Disclaimer

The released software is an initial development release version: 
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

To start the service use: 

```bash
./gradlew bootRun
```

To build a local docker image of the service use:

```bash
./gradlew bootBuildImage
```

## Endpoints

An OpenAPI specification of the endpoints provided by Trust Validator Service is available [here](src/main/resources/public/openapi.json).

Swagger UI is also available at `/swagger-ui`.

## Configuration

Trust Validator Service can be configured using the following *environment* variables:

### Server Configuration

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

### DSS Configuration

Variable: `TRUST_VALIDATOR_DSS_CACHE_LOCATION`  
Description: Path to the directory where DSS will cache LoTLs

### Trust Sources – Wallet Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WALLET_PROVIDERS_LOCATION`  
Description: URL of the LoTL from which to load Trust Anchors for Wallet Providers  

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WALLET_PROVIDERS_SIGNATURE_VERIFICATION_LOCATION`  
Description: Location of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL, uses Spring Resource notation  

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WALLET_PROVIDERS_SIGNATURE_VERIFICATION_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WALLET_PROVIDERS_SIGNATURE_VERIFICATION_PASSWORD`  
Description: Password of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL  

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WALLET_PROVIDERS_ISSUANCE_SERVICE`  
Description: Service Type Identifier of the Issuance Service, must be a valid URI  

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WALLET_PROVIDERS_REVOCATION_SERVICE`  
Description: Service Type Identifier of the Revocation Service, must be a valid URI

### Trust Sources – PID Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PID_PROVIDERS_LOCATION`  
Description: URL of the LoTL from which to load Trust Anchors for PID Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PID_PROVIDERS_SIGNATURE_VERIFICATION_LOCATION`  
Description: Location of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL, uses Spring Resource notation

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PID_PROVIDERS_SIGNATURE_VERIFICATION_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PID_PROVIDERS_SIGNATURE_VERIFICATION_PASSWORD`  
Description: Password of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PID_PROVIDERS_ISSUANCE_SERVICE`  
Description: Service Type Identifier of the Issuance Service, must be a valid URI

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PID_PROVIDERS_REVOCATION_SERVICE`  
Description: Service Type Identifier of the Revocation Service, must be a valid URI

### Trust Sources – QEAA Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_QEAA_PROVIDERS_LOCATION`  
Description: URL of the LoTL from which to load Trust Anchors for QEAA Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_QEAA_PROVIDERS_SIGNATURE_VERIFICATION_LOCATION`  
Description: Location of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL, uses Spring Resource notation

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_QEAA_PROVIDERS_SIGNATURE_VERIFICATION_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_QEAA_PROVIDERS_SIGNATURE_VERIFICATION_PASSWORD`  
Description: Password of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_QEAA_PROVIDERS_ISSUANCE_SERVICE`  
Description: Service Type Identifier of the Issuance Service, must be a valid URI

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_QEAA_PROVIDERS_REVOCATION_SERVICE`  
Description: Service Type Identifier of the Revocation Service, must be a valid URI

### Trust Sources – PubEAA Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PUB_EAA_PROVIDERS_LOCATION`  
Description: URL of the LoTL from which to load Trust Anchors for PubEAA Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PUB_EAA_PROVIDERS_SIGNATURE_VERIFICATION_LOCATION`  
Description: Location of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL, uses Spring Resource notation

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PUB_EAA_PROVIDERS_SIGNATURE_VERIFICATION_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PUB_EAA_PROVIDERS_SIGNATURE_VERIFICATION_PASSWORD`  
Description: Password of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PUB_EAA_PROVIDERS_ISSUANCE_SERVICE`  
Description: Service Type Identifier of the Issuance Service, must be a valid URI

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_PUB_EAA_PROVIDERS_REVOCATION_SERVICE`  
Description: Service Type Identifier of the Revocation Service, must be a valid URI

### Trust Sources – EAA Providers

Trust Validator Service allows configuring multiple EAA Providers. Each EAA Provider corresponds to a different use-case.

> [!NOTE]
> 
> Substitute `XXX` with the index of the EAA Provider you are configuring.

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_EAA_PROVIDERS_XXX_USE_CASE`    
Description: The use-case of the EAA Provider  
Example: `mDL`  

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_EAA_PROVIDERS_XXX_LOTL_LOCATION`  
Description: URL of the LoTL from which to load Trust Anchors for the current EAA Provider

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_EAA_PROVIDERS_XXX_LOTL_SIGNATURE_VERIFICATION_LOCATION`  
Description: Location of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL, uses Spring Resource notation

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_EAA_PROVIDERS_XXX_LOTL_SIGNATURE_VERIFICATION_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_EAA_PROVIDERS_XXX_LOTL_SIGNATURE_VERIFICATION_PASSWORD`  
Description: Password of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_EAA_PROVIDERS_XXX_LOTL_ISSUANCE_SERVICE`  
Description: Service Type Identifier of the Issuance Service, must be a valid URI

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_EAA_PROVIDERS_XXX_LOTL_REVOCATION_SERVICE`  
Description: Service Type Identifier of the Revocation Service, must be a valid URI

### Trust Sources – Wallet Relying Party Access Certificate Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPAC_PROVIDERS_LOCATION`  
Description: URL of the LoTL from which to load Trust Anchors for Wallet Relying Party Access Certificate Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPAC_PROVIDERS_SIGNATURE_VERIFICATION_LOCATION`  
Description: Location of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL, uses Spring Resource notation

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPAC_PROVIDERS_SIGNATURE_VERIFICATION_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPAC_PROVIDERS_SIGNATURE_VERIFICATION_PASSWORD`  
Description: Password of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPAC_PROVIDERS_ISSUANCE_SERVICE`  
Description: Service Type Identifier of the Issuance Service, must be a valid URI

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPAC_PROVIDERS_REVOCATION_SERVICE`  
Description: Service Type Identifier of the Revocation Service, must be a valid URI

### Trust Sources – Wallet Relying Party Registration Certificate Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPRC_PROVIDERS_LOCATION`  
Description: URL of the LoTL from which to load Trust Anchors for Wallet Relying Party Registration Certificate Providers

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPRC_PROVIDERS_SIGNATURE_VERIFICATION_LOCATION`  
Description: Location of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL, uses Spring Resource notation

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPRC_PROVIDERS_SIGNATURE_VERIFICATION_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPRC_PROVIDERS_SIGNATURE_VERIFICATION_PASSWORD`  
Description: Password of the Java KeyStore that contains X.509 certificates that can be used to verify the signature of the LoTL

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPRC_PROVIDERS_ISSUANCE_SERVICE`  
Description: Service Type Identifier of the Issuance Service, must be a valid URI

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_WRPRC_PROVIDERS_REVOCATION_SERVICE`  
Description: Service Type Identifier of the Revocation Service, must be a valid URI

### Trust Sources – Java KeyStore

Trust Validator Service allows configuring a Java KeyStore that contains Trust Anchors. These Trust Anchors are used to verify any type of Provider.

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_KEY_STORE_LOCATION`  
Description: Location of the Java KeyStore that contains Trust Anchors, uses Spring Resource notation  

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_KEY_STORE_KEY_STORE_TYPE`  
Description: Type of the Java KeyStore that contains Trust Anchors   
Default value: `JKS`

Variable: `TRUST_VALIDATOR_TRUST_SOURCES_KEY_STORE_PASSWORD`  
Description: Password of the Java KeyStore that contains Trust Anchors  

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone  
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2025-2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

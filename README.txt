Nimbus OAuth 2.0 SDK with OpenID Connect extensions

Copyright (c) Connect2id Ltd., 2012 - 2017


README

This open source Java library is your starting point for developing OAuth 2.0
and OpenID Connect based applications:

	* Developing OAuth 2.0 servers:

		- Parse and process requests at the Authorisation Endpoint, then
		  generate the appropriate responses with an authorisation code or
		  access token;

		- Parse and process requests at the Token Endpoint, then generate the
		  appropriate responses;

		- Parse and process requests at the Token Introspection Endpoint;

		- Parse and process requests at the Token Revocation Endpoint;

		- Parse and process requests at the Client Registration Endpoint, then
		  generate the appropriate responses.

	* Developing OAuth 2.0 clients:

		- Make requests to an OAuth 2.0 Authorisation Endpoint and parse the
		  responses;

		- Make requests to an OAuth 2.0 Token Endpoint and parse the responses;

		- Make requests to an OAuth 2.0 Token Introspection Endpoint and
		  process the responses;

		- Make requests to an OAuth 2.0 Token Revocation Endpoint and parse the
		  responses;

		- Make requests to a protected resource using an OAuth 2.0
		  access token.

	* Developing OpenID Connect provider (OP) servers:
	
		- Parse and process requests at the OpenID Connect Authorisation
		  Endpoint, then generate the appropriate responses with an
		  authorisation code, ID Token and / or UserInfo access token;
		  
		- Parse and process requests at the OpenID Connect Token Endpoint, then
		  generate the appropriate responses;
		  
		- Parse and process requests at the OpenID Connect UserInfo Endpoint,
		  then generate the appropriate responses;
		  
		- Parse and process requests at the OpenID Connect Client Registration
		  Endpoint, then generate the appropriate responses;

		- Parse and process requests at the OpenID Connect End-Session (Logout)
		  Endpoint.

		- Make requests to a Relying Party Back-Channel Logout Endpoint.
	
	* Developing OpenID Connect relying party (RP) clients:
	
		- Make requests to an OpenID Connect Authorisation Endpoint and process
		  the responses;
		  
		- Make requests to an OpenID Connect Token Endpoint and process the
		  responses;
		  
		- Make requests to an OpenID Connect UserInfo Endpoint and process the
		  responses;
		  
		- Make requests to an OpenID Connect Client Registration Endpoint and
		  process the responses.

		- Make requests to an OpenID Connect End-Session (Logout) Endpoint.

		- Parse and process requests at a Back-Channel Logout Endpoint.


Additional features:

	* Process plain, signed and encrypted JSON Web Tokens (JWTs) with help 
	  of the Nimbus JOSE+JWT library.

	* Full OpenID Connect UserInfo i10n and l10n support with help of the
	  Nimbus Language Tags (RFC 5646) library.


This SDK version implements the following standards and drafts:

	* The OAuth 2.0 Authorization Framework (RFC 6749)

	* The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)

	* OAuth 2.0 Token Introspection (RFC 7662)

	* OAuth 2.0 Token Revocation (RFC 7009)

	* OAuth 2.0 Authorization Server Metadata (draft-ietf-oauth-discovery-04)

	* OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)

	* OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)

	* Assertion Framework for OAuth 2.0 Client Authentication and Authorization
	  Grants (RFC 7521)

	* JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
      Authorization Grants (RFC 7523)

    * SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization
      Grants (RFC 7522)

    * Proof Key for Code Exchange by OAuth Public Clients (RFC 7636)

    * Authentication Method Reference Values (draft-ietf-oauth-amr-values-01)

	* OpenID Connect Core 1.0 (2014-02-25).

	* OpenID Connect Discovery 1.0 (2014-02-25).

	* OpenID Connect Dynamic Registration 1.0 (2014-02-25).

	* OpenID Connect Session Management 1.0 (2017-01-25).

	* OpenID Connect Front-Channel Logout 1.0 (2017-01-25).

	* OpenID Connect Back-Channel Logout 1.0 (2017-01-25).

	* OAuth 2.0 Multiple Response Type Encoding Practices 1.0 (2014-02-25).


This SDK is provided under the terms of the Apache 2.0 licence.


Questions or comments? Email support@connect2id.com


2016-04-10


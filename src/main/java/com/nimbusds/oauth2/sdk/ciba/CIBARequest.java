/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.oauth2.sdk.ciba;


import java.net.URI;
import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.AbstractAuthenticatedRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.*;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;


/**
 * <p>CIBA request to an OpenID provider / OAuth 2.0 authorisation server
 * backend authentication endpoint. Supports plan as well as signed (JWT)
 * requests.
 *
 * <p>Example HTTP request:
 * 
 * <pre>
 * POST /bc-authorize HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * scope=openid%20email%20example-scope&amp;
 * client_notification_token=8d67dc78-7faa-4d41-aabd-67707b374255&amp;
 * binding_message=W4SCT&amp;
 * login_hint_token=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ
 * zdWJfaWQiOnsic3ViamVjdF90eXBlIjoicGhvbmUiLCJwaG9uZSI6IisxMzMwMjg
 * xODAwNCJ9fQ.Kk8jcUbHjJAQkRSHyDuFQr3NMEOSJEZc85VfER74tX6J9CuUllr8
 * 9WKUHUR7MA0-mWlptMRRhdgW1ZDt7g1uwQ&amp;
 * client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A
 * client-assertion-type%3Ajwt-bearer&amp;
 * client_assertion=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ
 * pc3MiOiJzNkJoZFJrcXQzIiwic3ViIjoiczZCaGRSa3F0MyIsImF1ZCI6Imh0dHB
 * zOi8vc2VydmVyLmV4YW1wbGUuY29tIiwianRpIjoiYmRjLVhzX3NmLTNZTW80RlN
 * 6SUoyUSIsImlhdCI6MTUzNzgxOTQ4NiwiZXhwIjoxNTM3ODE5Nzc3fQ.Ybr8mg_3
 * E2OptOSsA8rnelYO_y1L-yFaF_j1iemM3ntB61_GN3APe5cl_-5a6cvGlP154XAK
 * 7fL-GaZSdnd9kg
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0, section 7.1.
 * </ul>
 */
@Immutable
public class CIBARequest extends AbstractAuthenticatedRequest {
	
	
	/**
	 * The maximum allowed length of a client notification token.
	 */
	public static final int CLIENT_NOTIFICATION_TOKEN_MAX_LENGTH = 1024;
	

	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;

	static {
		Set<String> p = new HashSet<>();

		// Plain
		p.add("scope");
		p.add("client_notification_token");
		p.add("acr_values");
		p.add("login_hint_token");
		p.add("id_token_hint");
		p.add("login_hint");
		p.add("binding_message");
		p.add("user_code");
		p.add("requested_expiry");
		p.add("claims");
		p.add("claims_locales");
		p.add("purpose");
		p.add("resource");
		
		// Signed JWT
		p.add("request");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}

	
	/**
	 * The scope (required), must contain {@code openid}.
	 */
	private final Scope scope;

	
	/**
	 * The client notification token, required for the CIBA ping and push
	 * token delivery modes.
	 */
	private final BearerAccessToken clientNotificationToken;
	
	
	/**
	 * Requested Authentication Context Class Reference values (optional).
	 */
	private final List<ACR> acrValues;
	
	
	/**
	 * A token containing information identifying the end-user for whom
	 * authentication is being requested (optional).
	 */
	private final String loginHintTokenString;
	
	
	/**
	 * Previously issued ID token passed as a hint to identify the end-user
	 * for whom authentication is being requested (optional).
	 */
	private final JWT idTokenHint;
	
	
	/**
	 * Login hint (email address, phone number, etc) about the end-user for
	 * whom authentication is being requested (optional).
	 */
	private final String loginHint;
	
	
	/**
	 * Human-readable binding message for the display at the consumption
	 * and authentication devices (optional).
	 */
	private final String bindingMessage;
	
	
	/**
	 * User secret code (password, PIN, etc.) to authorise the CIBA request
	 * with the authentication device (optional).
	 */
	private final Secret userCode;
	
	
	/**
	 * Requested expiration for the {@code auth_req_id} (optional).
	 */
	private final Integer requestedExpiry;
	
	
	/**
	 * Individual claims to be returned (optional).
	 */
	private final OIDCClaimsRequest claims;
	
	
	/**
	 * The end-user's preferred languages and scripts for claims being
	 * returned (optional).
	 */
	private final List<LangTag> claimsLocales;
	
	
	/**
	 * The transaction specific purpose, for use in OpenID Connect Identity
	 * Assurance.
	 */
	private final String purpose;
	
	
	/**
	 * The resource URI(s) (optional).
	 */
	private final List<URI> resources;
	
	
	/**
	 * Custom parameters.
	 */
	private final Map<String,List<String>> customParams;
	
	
	/**
	 * The JWT for a signed request.
	 */
	private final SignedJWT signedRequest;
	

	/**
	 * Builder for constructing CIBA requests.
	 */
	public static class Builder {

		
		/**
		 * The endpoint URI (optional).
		 */
		private URI uri;
		
		
		/**
		 * The client authentication (required).
		 */
		private final ClientAuthentication clientAuth;
		
		
		/**
		 * The scope (required).
		 */
		private final Scope scope;
		
		
		/**
		 * The client notification type, required for the CIBA ping and
		 * push token delivery modes.
		 */
		private BearerAccessToken clientNotificationToken;
		
		
		/**
		 * Requested Authentication Context Class Reference values
		 * (optional).
		 */
		private List<ACR> acrValues;
		
		
		/**
		 * A token containing information identifying the end-user for
		 * whom authentication is being requested (optional).
		 */
		private String loginHintTokenString;
		
		
		/**
		 * Previously issued ID token passed as a hint to identify the
		 * end-user for whom authentication is being requested
		 * (optional).
		 */
		private JWT idTokenHint;
		
		
		/**
		 * Identity hint (email address, phone number, etc) about the
		 * end-user for whom authentication is being requested
		 * (optional).
		 */
		private String loginHint;
		
		
		/**
		 * Human readable binding message for the display at the
		 * consumption and authentication devices (optional).
		 */
		private String bindingMessage;
		
		
		/**
		 * User secret code (password, PIN, etc) to authorise the CIBA
		 * request with the authentication device (optional).
		 */
		private Secret userCode;
		
		
		/**
		 * Requested expiration for the {@code auth_req_id} (optional).
		 */
		private Integer requestedExpiry;
		
		
		/**
		 * Individual claims to be returned (optional).
		 */
		private OIDCClaimsRequest claims;
		
		
		/**
		 * The end-user's preferred languages and scripts for claims
		 * being returned (optional).
		 */
		private List<LangTag> claimsLocales;
		
		
		/**
		 * The transaction specific purpose (optional).
		 */
		private String purpose;
		
		
		/**
		 * The resource URI(s) (optional).
		 */
		private List<URI> resources;
		
		
		/**
		 * Custom parameters.
		 */
		private Map<String,List<String>> customParams = new HashMap<>();
		
		
		/**
		 * The JWT for a signed request.
		 */
		private final SignedJWT signedRequest;

		
		/**
		 * Creates a new CIBA request builder.
		 *
		 * @param clientAuth The client authentication. Must not be
		 *                   {@code null}.
		 * @param scope      The requested scope, {@code null} if not
		 *                   specified.
		 */
		public Builder(final ClientAuthentication clientAuth,
			       final Scope scope) {
			
			if (clientAuth == null) {
				throw new IllegalArgumentException("The client authentication must not be null");
			}
			this.clientAuth = clientAuth;
			
			this.scope = scope;
			
			signedRequest = null;
		}
		
		
		/**
		 * Creates a new CIBA signed request builder.
		 *
		 * @param clientAuth    The client authentication. Must not be
		 *                      {@code null}.
		 * @param signedRequest The signed request JWT. Must not be
		 *                      {@code null}.
		 */
		public Builder(final ClientAuthentication clientAuth,
			       final SignedJWT signedRequest) {
			
			if (clientAuth == null) {
				throw new IllegalArgumentException("The client authentication must not be null");
			}
			this.clientAuth = clientAuth;
			
			if (signedRequest == null) {
				throw new IllegalArgumentException("The signed request JWT must not be null");
			}
			this.signedRequest = signedRequest;
			
			scope = null;
		}
		

		/**
		 * Creates a new CIBA request builder from the specified
		 * request.
		 *
		 * @param request The CIBA request. Must not be {@code null}.
		 */
		public Builder(final CIBARequest request) {
			
			uri = request.getEndpointURI();
			clientAuth = request.getClientAuthentication();
			scope = request.getScope();
			clientNotificationToken = request.getClientNotificationToken();
			acrValues = request.getACRValues();
			loginHintTokenString = request.getLoginHintTokenString();
			idTokenHint = request.getIDTokenHint();
			loginHint = request.getLoginHint();
			bindingMessage = request.getBindingMessage();
			userCode = request.getUserCode();
			requestedExpiry = request.getRequestedExpiry();
			claims = request.getOIDCClaims();
			claimsLocales = request.getClaimsLocales();
			purpose = request.getPurpose();
			resources = request.getResources();
			customParams = request.getCustomParameters();
			signedRequest = request.getRequestJWT();
		}
		
		
		/**
		 * Sets the client notification token, required for the CIBA
		 * ping and push token delivery modes. Corresponds to the
		 * {@code client_notification_token} parameter.
		 *
		 * @param token The client notification token, {@code null} if
		 *              not specified.
		 *
		 * @return This builder.
		 */
		public Builder clientNotificationToken(final BearerAccessToken token) {
			this.clientNotificationToken = token;
			return this;
		}

		
		/**
		 * Sets the requested Authentication Context Class Reference
		 * values. Corresponds to the optional {@code acr_values}
		 * parameter.
		 *
		 * @param acrValues The requested ACR values, {@code null} if
		 *                  not specified.
		 *
		 * @return This builder.
		 */
		public Builder acrValues(final List<ACR> acrValues) {
			this.acrValues = acrValues;
			return this;
		}
		
		
		/**
		 * Sets the login hint token string, containing information
		 * identifying the end-user for whom authentication is being requested.
		 * Corresponds to the {@code login_hint_token} parameter.
		 *
		 * @param loginHintTokenString The login hint token string,
		 *                             {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder loginHintTokenString(final String loginHintTokenString) {
			this.loginHintTokenString = loginHintTokenString;
			return this;
		}
		
		
		/**
		 * Sets the ID Token hint, passed as a hint to identify the
		 * end-user for whom authentication is being requested.
		 * Corresponds to the {@code id_token_hint} parameter.
		 *
		 * @param idTokenHint The ID Token hint, {@code null} if not
		 *                    specified.
		 *
		 * @return This builder.
		 */
		public Builder idTokenHint(final JWT idTokenHint) {
			this.idTokenHint = idTokenHint;
			return this;
		}
		
		
		/**
		 * Sets the login hint (email address, phone number, etc),
		 * about the end-user for whom authentication is being
		 * requested. Corresponds to the {@code login_hint} parameter.
		 *
		 * @param loginHint The login hint, {@code null} if not
		 *                  specified.
		 *
		 * @return This builder.
		 */
		public Builder loginHint(final String loginHint) {
			this.loginHint = loginHint;
			return this;
		}
		
		
		/**
		 * Sets the human readable binding message for the display at
		 * the consumption and authentication devices. Corresponds to
		 * the {@code binding_message} parameter.
		 *
		 * @param bindingMessage The binding message, {@code null} if
		 *                       not specified.
		 *
		 * @return This builder.
		 */
		public Builder bindingMessage(final String bindingMessage) {
			this.bindingMessage = bindingMessage;
			return this;
		}
		
		
		/**
		 * Gets the user secret code (password, PIN, etc) to authorise
		 * the CIBA request with the authentication device. Corresponds
		 * to the {@code user_code} parameter.
		 *
		 * @param userCode The user code, {@code null} if not
		 *                 specified.
		 *
		 * @return This builder.
		 */
		public Builder userCode(final Secret userCode) {
			this.userCode = userCode;
			return this;
		}
		
		
		/**
		 * Sets the requested expiration for the {@code auth_req_id}.
		 * Corresponds to the {@code requested_expiry} parameter.
		 *
		 * @param requestedExpiry The required expiry (as positive
		 *                        integer), {@code null} if not
		 *                        specified.
		 *
		 * @return This builder.
		 */
		public Builder requestedExpiry(final Integer requestedExpiry) {
			this.requestedExpiry = requestedExpiry;
			return this;
		}
		
		
		/**
		 * Sets the individual OpenID claims to be returned.
		 * Corresponds to the optional {@code claims} parameter.
		 *
		 * @param claims The individual OpenID claims to be returned,
		 *               {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder claims(final OIDCClaimsRequest claims) {
			
			this.claims = claims;
			return this;
		}
		
		
		/**
		 * Sets the end-user's preferred languages and scripts for the
		 * claims being returned, ordered by preference. Corresponds to
		 * the optional {@code claims_locales} parameter.
		 *
		 * @param claimsLocales The preferred claims locales,
		 *                      {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder claimsLocales(final List<LangTag> claimsLocales) {
			
			this.claimsLocales = claimsLocales;
			return this;
		}
		
		
		/**
		 * Sets the transaction specific purpose. Corresponds to the
		 * optional {@code purpose} parameter.
		 *
		 * @param purpose The purpose, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder purpose(final String purpose) {
			
			this.purpose = purpose;
			return this;
		}
		
		
		/**
		 * Sets the resource server URI.
		 *
		 * @param resource The resource URI, {@code null} if not
		 *                 specified.
		 *
		 * @return This builder.
		 */
		public Builder resource(final URI resource) {
			if (resource != null) {
				this.resources = Collections.singletonList(resource);
			} else {
				this.resources = null;
			}
			return this;
		}
		
		
		/**
		 * Sets the resource server URI(s).
		 *
		 * @param resources The resource URI(s), {@code null} if not
		 *                  specified.
		 *
		 * @return This builder.
		 */
		public Builder resources(final URI ... resources) {
			if (resources != null) {
				this.resources = Arrays.asList(resources);
			} else {
				this.resources = null;
			}
			return this;
		}
		
		
		/**
		 * Sets a custom parameter.
		 *
		 * @param name   The parameter name. Must not be {@code null}.
		 * @param values The parameter values, {@code null} if not
		 *               specified.
		 *
		 * @return This builder.
		 */
		public Builder customParameter(final String name, final String ... values) {
			
			if (values == null || values.length == 0) {
				customParams.remove(name);
			} else {
				customParams.put(name, Arrays.asList(values));
			}
			
			return this;
		}
		
		
		/**
		 * Sets the URI of the endpoint (HTTP or HTTPS) for which the
		 * request is intended.
		 *
		 * @param uri The endpoint URI, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder endpointURI(final URI uri) {
			
			this.uri = uri;
			return this;
		}
		
		
		/**
		 * Builds a new CIBA request.
		 *
		 * @return The CIBA request.
		 */
		public CIBARequest build() {
			
			try {
				if (signedRequest != null) {
					return new CIBARequest(
						uri,
						clientAuth,
						signedRequest
					);
				}
				
				// Plain request
				return new CIBARequest(
					uri,
					clientAuth,
					scope,
					clientNotificationToken,
					acrValues,
					loginHintTokenString,
					idTokenHint,
					loginHint,
					bindingMessage,
					userCode,
					requestedExpiry,
					claims,
					claimsLocales,
					purpose,
					resources,
					customParams
				);
			} catch (IllegalArgumentException e) {
				throw new IllegalArgumentException(e.getMessage(), e);
			}
		}
	}
	
	
	/**
	 * Creates a new CIBA request.
	 *
	 * @param uri                     The endpoint URI, {@code null} if not
	 *                                specified.
	 * @param clientAuth              The client authentication. Must not
	 *                                be {@code null}.
	 * @param scope                   The requested scope. Must not be
	 *                                empty or {@code null}.
	 * @param clientNotificationToken The client notification token,
	 *                                {@code null} if not specified.
	 * @param acrValues               The requested ACR values,
	 *                                {@code null} if not specified.
	 * @param loginHintTokenString    The login hint token string,
	 *                                {@code null} if not specified.
	 * @param idTokenHint             The ID Token hint, {@code null} if
	 *                                not specified.
	 * @param loginHint               The login hint, {@code null} if not
	 *                                specified.
	 * @param bindingMessage          The binding message, {@code null} if
	 *                                not specified.
	 * @param userCode                The user code, {@code null} if not
	 *                                specified.
	 * @param requestedExpiry         The required expiry (as positive
	 *                                integer), {@code null} if not
	 *                                specified.
	 * @param customParams            Custom parameters, empty or
	 *                                {@code null} if not specified.
	 */
	@Deprecated
	public CIBARequest(final URI uri,
			   final ClientAuthentication clientAuth,
			   final Scope scope,
			   final BearerAccessToken clientNotificationToken,
			   final List<ACR> acrValues,
			   final String loginHintTokenString,
			   final JWT idTokenHint,
			   final String loginHint,
			   final String bindingMessage,
			   final Secret userCode,
			   final Integer requestedExpiry,
			   final Map<String, List<String>> customParams) {
		
		this(uri, clientAuth,
			scope, clientNotificationToken, acrValues,
			loginHintTokenString, idTokenHint, loginHint,
			bindingMessage, userCode, requestedExpiry,
			null, customParams);
	}
	
	
	/**
	 * Creates a new CIBA request.
	 *
	 * @param uri                     The endpoint URI, {@code null} if not
	 *                                specified.
	 * @param clientAuth              The client authentication. Must not
	 *                                be {@code null}.
	 * @param scope                   The requested scope. Must not be
	 *                                empty or {@code null}.
	 * @param clientNotificationToken The client notification token,
	 *                                {@code null} if not specified.
	 * @param acrValues               The requested ACR values,
	 *                                {@code null} if not specified.
	 * @param loginHintTokenString    The login hint token string,
	 *                                {@code null} if not specified.
	 * @param idTokenHint             The ID Token hint, {@code null} if
	 *                                not specified.
	 * @param loginHint               The login hint, {@code null} if not
	 *                                specified.
	 * @param bindingMessage          The binding message, {@code null} if
	 *                                not specified.
	 * @param userCode                The user code, {@code null} if not
	 *                                specified.
	 * @param requestedExpiry         The required expiry (as positive
	 *                                integer), {@code null} if not
	 *                                specified.
	 * @param claims                  The individual claims to be returned,
	 *                                {@code null} if not specified.
	 * @param customParams            Custom parameters, empty or
	 *                                {@code null} if not specified.
	 */
	@Deprecated
	public CIBARequest(final URI uri,
			   final ClientAuthentication clientAuth,
			   final Scope scope,
			   final BearerAccessToken clientNotificationToken,
			   final List<ACR> acrValues,
			   final String loginHintTokenString,
			   final JWT idTokenHint,
			   final String loginHint,
			   final String bindingMessage,
			   final Secret userCode,
			   final Integer requestedExpiry,
			   final OIDCClaimsRequest claims,
			   final Map<String, List<String>> customParams) {
		
		this(uri, clientAuth,
			scope, clientNotificationToken, acrValues,
			loginHintTokenString, idTokenHint, loginHint,
			bindingMessage, userCode, requestedExpiry,
			claims, null, null,
			null,
			customParams);
	}
	
	
	/**
	 * Creates a new CIBA request.
	 *
	 * @param uri                     The endpoint URI, {@code null} if not
	 *                                specified.
	 * @param clientAuth              The client authentication. Must not
	 *                                be {@code null}.
	 * @param scope                   The requested scope. Must not be
	 *                                empty or {@code null}.
	 * @param clientNotificationToken The client notification token,
	 *                                {@code null} if not specified.
	 * @param acrValues               The requested ACR values,
	 *                                {@code null} if not specified.
	 * @param loginHintTokenString    The login hint token string,
	 *                                {@code null} if not specified.
	 * @param idTokenHint             The ID Token hint, {@code null} if
	 *                                not specified.
	 * @param loginHint               The login hint, {@code null} if not
	 *                                specified.
	 * @param bindingMessage          The binding message, {@code null} if
	 *                                not specified.
	 * @param userCode                The user code, {@code null} if not
	 *                                specified.
	 * @param requestedExpiry         The required expiry (as positive
	 *                                integer), {@code null} if not
	 *                                specified.
	 * @param claims                  The individual claims to be
	 *                                returned, {@code null} if not
	 *                                specified.
	 * @param claimsLocales           The preferred languages and scripts
	 *                                for claims being returned,
	 *                                {@code null} if not specified.
	 * @param purpose                 The transaction specific purpose,
	 *                                {@code null} if not specified.
	 * @param resources               The resource URI(s), {@code null} if
	 *                                not specified.
	 * @param customParams            Custom parameters, empty or
	 *                                {@code null} if not specified.
	 */
	public CIBARequest(final URI uri,
			   final ClientAuthentication clientAuth,
			   final Scope scope,
			   final BearerAccessToken clientNotificationToken,
			   final List<ACR> acrValues,
			   final String loginHintTokenString,
			   final JWT idTokenHint,
			   final String loginHint,
			   final String bindingMessage,
			   final Secret userCode,
			   final Integer requestedExpiry,
			   final OIDCClaimsRequest claims,
			   final List<LangTag> claimsLocales,
			   final String purpose,
			   final List<URI> resources,
			   final Map<String, List<String>> customParams) {
		
		super(uri, clientAuth);
		
		this.scope = scope;
		
		if (clientNotificationToken != null && clientNotificationToken.getValue().length() > CLIENT_NOTIFICATION_TOKEN_MAX_LENGTH) {
			throw new IllegalArgumentException("The client notification token must not exceed " + CLIENT_NOTIFICATION_TOKEN_MAX_LENGTH + " chars");
		}
		this.clientNotificationToken = clientNotificationToken;
		
		this.acrValues = acrValues;
		
		// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-03.html#rfc.section.7.1
		// As in the CIBA flow the OP does not have an interaction with
		// the end-user through the consumption device, it is REQUIRED
		// that the Client provides one (and only one) of the hints
		// specified above in the authentication request, that is
		// "login_hint_token", "id_token_hint" or "login_hint".
		int numHints = 0;
		
		if (loginHintTokenString != null) numHints++;
		this.loginHintTokenString = loginHintTokenString;
		
		if (idTokenHint != null) numHints++;
		this.idTokenHint = idTokenHint;
		
		if (loginHint != null) numHints++;
		this.loginHint = loginHint;
		
		if (numHints != 1) {
			throw new IllegalArgumentException("One user identity hist must be provided (login_hint_token, id_token_hint or login_hint)");
		}
		
		this.bindingMessage = bindingMessage;
		
		this.userCode = userCode;
		
		if (requestedExpiry != null && requestedExpiry < 1) {
			throw new IllegalArgumentException("The requested expiry must be a positive integer");
		}
		this.requestedExpiry = requestedExpiry;
		
		this.claims = claims;
		
		if (claimsLocales != null) {
			this.claimsLocales = Collections.unmodifiableList(claimsLocales);
		} else {
			this.claimsLocales = null;
		}
		
		this.purpose = purpose;
		
		this.resources = ResourceUtils.ensureLegalResourceURIs(resources);
		
		this.customParams = customParams != null ? customParams : Collections.<String, List<String>>emptyMap();
		
		signedRequest = null;
	}
	
	
	/**
	 * Creates a new CIBA signed request.
	 *
	 * @param uri           The endpoint URI, {@code null} if not
	 *                      specified.
	 * @param clientAuth    The client authentication. Must not be
	 *                      {@code null}.
	 * @param signedRequest The signed request JWT. Must not be
	 *                      {@code null}.
	 */
	public CIBARequest(final URI uri,
			   final ClientAuthentication clientAuth,
			   final SignedJWT signedRequest) {
		
		super(uri, clientAuth);
		
		if (signedRequest == null) {
			throw new IllegalArgumentException("The signed request JWT must not be null");
		}
		if (JWSObject.State.UNSIGNED.equals(signedRequest.getState())) {
			throw new IllegalArgumentException("The request JWT must be in a signed state");
		}
		this.signedRequest = signedRequest;
		
		scope = null;
		clientNotificationToken = null;
		acrValues = null;
		loginHintTokenString = null;
		idTokenHint = null;
		loginHint = null;
		bindingMessage = null;
		userCode = null;
		requestedExpiry = null;
		claims = null;
		claimsLocales = null;
		purpose = null;
		resources = null;
		customParams = Collections.emptyMap();
	}

	
	/**
	 * Returns the registered (standard) CIBA request parameter names.
	 *
	 * @return The registered CIBA request parameter names, as a
	 *         unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}

	
	/**
	 * Returns the scope. Corresponds to the optional {@code scope}
	 * parameter.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}
	
	
	/**
	 * Returns the client notification token, required for the CIBA ping
	 * and push token delivery modes. Corresponds to the
	 * {@code client_notification_token} parameter.
	 *
	 * @return The client notification token, {@code null} if not
	 *         specified.
	 */
	public BearerAccessToken getClientNotificationToken() {
		
		return clientNotificationToken;
	}
	
	
	/**
	 * Returns the requested Authentication Context Class Reference values.
	 * Corresponds to the optional {@code acr_values} parameter.
	 *
	 * @return The requested ACR values, {@code null} if not specified.
	 */
	public List<ACR> getACRValues() {
		
		return acrValues;
	}
	
	
	/**
	 * Returns the hint type.
	 *
	 * @return The hint type.
	 */
	public CIBAHintType getHintType() {
		
		if (getLoginHintTokenString() != null) {
			return CIBAHintType.LOGIN_HINT_TOKEN;
		} else if (getIDTokenHint() != null) {
			return CIBAHintType.ID_TOKEN_HINT;
		} else {
			return CIBAHintType.LOGIN_HINT;
		}
	}
	
	
	/**
	 * Returns the login hint token string, containing information
	 * identifying the end-user for whom authentication is being requested.
	 * Corresponds to the {@code login_hint_token} parameter.
	 *
	 * @return The login hint token string, {@code null} if not
	 *         specified.
	 */
	public String getLoginHintTokenString() {
		
		return loginHintTokenString;
	}
	
	
	/**
	 * Returns the ID Token hint, passed as a hint to identify the end-user
	 * for whom authentication is being requested. Corresponds to the
	 * {@code id_token_hint} parameter.
	 *
	 * @return The ID Token hint, {@code null} if not specified.
	 */
	public JWT getIDTokenHint() {
		
		return idTokenHint;
	}
	
	
	/**
	 * Returns the login hint (email address, phone number, etc), about the
	 * end-user for whom authentication is being requested. Corresponds to
	 * the {@code login_hint} parameter.
	 *
	 * @return The login hint, {@code null} if not specified.
	 */
	public String getLoginHint() {
		
		return loginHint;
	}
	
	
	/**
	 * Returns the human-readable binding message for the display at the
	 * consumption and authentication devices. Corresponds to the
	 * {@code binding_message} parameter.
	 *
	 * @return The binding message, {@code null} if not specified.
	 */
	public String getBindingMessage() {
		
		return bindingMessage;
	}
	
	
	/**
	 * Returns the user secret code (password, PIN, etc) to authorise the
	 * CIBA request with the authentication device. Corresponds to the
	 * {@code user_code} parameter.
	 *
	 * @return The user code, {@code null} if not specified.
	 */
	public Secret getUserCode() {
		
		return userCode;
	}
	
	
	/**
	 * Returns the requested expiration for the {@code auth_req_id}.
	 * Corresponds to the {@code requested_expiry} parameter.
	 *
	 * @return The required expiry (as positive integer), {@code null} if
	 *         not specified.
	 */
	public Integer getRequestedExpiry() {
		
		return requestedExpiry;
	}
	
	
	/**
	 * Returns the individual claims to be returned. Corresponds to the
	 * optional {@code claims} parameter.
	 *
	 * @return The individual claims to be returned, {@code null} if not
	 *         specified.
	 */
	public OIDCClaimsRequest getOIDCClaims() {
		
		return claims;
	}
	
	
	/**
	 * Returns the end-user's preferred languages and scripts for the
	 * claims being returned, ordered by preference. Corresponds to the
	 * optional {@code claims_locales} parameter.
	 *
	 * @return The preferred claims locales, {@code null} if not specified.
	 */
	public List<LangTag> getClaimsLocales() {
		
		return claimsLocales;
	}
	
	
	/**
	 * Returns the transaction specific purpose. Corresponds to the
	 * optional {@code purpose} parameter.
	 *
	 * @return The purpose, {@code null} if not specified.
	 */
	public String getPurpose() {
		
		return purpose;
	}
	
	
	/**
	 * Returns the resource server URI.
	 *
	 * @return The resource URI(s), {@code null} if not specified.
	 */
	public List<URI> getResources() {
		
		return resources;
	}
	
	
	/**
	 * Returns the additional custom parameters.
	 *
	 * @return The additional custom parameters as a unmodifiable map,
	 *         empty map if none.
	 */
	public Map<String, List<String>> getCustomParameters() {
		
		return customParams;
	}
	
	
	/**
	 * Returns the specified custom parameter.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 *
	 * @return The parameter value(s), {@code null} if not specified.
	 */
	public List<String> getCustomParameter(final String name) {
		
		return customParams.get(name);
	}
	
	
	/**
	 * Returns {@code true} if this request is signed.
	 *
	 * @return {@code true} for a signed request, {@code false} for a plain
	 *         request.
	 */
	public boolean isSigned() {
		
		return signedRequest != null;
	}
	
	
	/**
	 * Returns the JWT for a signed request.
	 *
	 * @return The request JWT.
	 */
	public SignedJWT getRequestJWT() {
		
		return signedRequest;
	}
	
	
	/**
	 * Returns the for parameters for this CIBA request. Parameters which
	 * are part of the client authentication are not included.
	 *
	 * @return The parameters.
	 */
	public Map<String, List<String>> toParameters() {
		
		// Put custom params first, so they may be overwritten by std params
		Map<String, List<String>> params = new LinkedHashMap<>(getCustomParameters());
		
		if (isSigned()) {
			params.put("request", Collections.singletonList(signedRequest.serialize()));
			return params;
		}

		if (CollectionUtils.isNotEmpty(getScope())) {
			params.put("scope", Collections.singletonList(getScope().toString()));
		}
		
		if (getClientNotificationToken() != null) {
			params.put("client_notification_token", Collections.singletonList(getClientNotificationToken().getValue()));
		}
		if (getACRValues() != null) {
			params.put("acr_values", Identifier.toStringList(getACRValues()));
		}
		if (getLoginHintTokenString() != null) {
			params.put("login_hint_token", Collections.singletonList(getLoginHintTokenString()));
		}
		if (getIDTokenHint() != null) {
			params.put("id_token_hint", Collections.singletonList(getIDTokenHint().serialize()));
		}
		if (getLoginHint() != null) {
			params.put("login_hint", Collections.singletonList(getLoginHint()));
		}
		if (getBindingMessage() != null) {
			params.put("binding_message", Collections.singletonList(getBindingMessage()));
		}
		if (getUserCode() != null) {
			params.put("user_code", Collections.singletonList(getUserCode().getValue()));
		}
		if (getRequestedExpiry() != null) {
			params.put("requested_expiry", Collections.singletonList(getRequestedExpiry().toString()));
		}
		if (getOIDCClaims() != null) {
			params.put("claims", Collections.singletonList(getOIDCClaims().toJSONString()));
		}
		if (CollectionUtils.isNotEmpty(getClaimsLocales())) {
			params.put("claims_locales", Collections.singletonList(LangTagUtils.concat(getClaimsLocales())));
		}
		if (getPurpose() != null) {
			params.put("purpose", Collections.singletonList(purpose));
		}
		if (CollectionUtils.isNotEmpty(getResources())) {
			params.put("resource", URIUtils.toStringList(getResources(), true));
		}
		
		return params;
	}
	
	
	/**
	 * Returns the parameters for this CIBA request as a JSON Web Token
	 * (JWT) claims set. Intended for creating a signed CIBA request.
	 *
	 * @return The parameters as JWT claim set.
	 */
	public JWTClaimsSet toJWTClaimsSet() {
		
		if (isSigned()) {
			throw new IllegalStateException();
		}
		
		return JWTClaimsSetUtils.toJWTClaimsSet(toParameters());
	}
	
	
	/**
	 * Returns the matching HTTP request.
	 *
	 * @return The HTTP request.
	 */
	@Override
	public HTTPRequest toHTTPRequest() {

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		getClientAuthentication().applyTo(httpRequest);

		Map<String, List<String>> params = httpRequest.getQueryParameters();
		params.putAll(toParameters());
		httpRequest.setBody(URLUtils.serializeParameters(params));
		
		return httpRequest;
	}

	
	/**
	 * Parses a CIBA request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The CIBA request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBARequest parse(final HTTPRequest httpRequest) throws ParseException {

		// Only HTTP POST accepted
		URI uri = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);
		
		if (clientAuth == null) {
			throw new ParseException("Missing required client authentication");
		}
		
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		
		String v;
		
		if (params.containsKey("request")) {
			// Signed request
			v = MultivaluedMapUtils.getFirstValue(params, "request");
			
			if (StringUtils.isBlank(v)) {
				throw new ParseException("Empty request parameter");
			}
			
			SignedJWT signedRequest;
			try {
				signedRequest = SignedJWT.parse(v);
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid request JWT: " + e.getMessage(), e);
			}
			
			try {
				return new CIBARequest(uri, clientAuth, signedRequest);
			} catch (IllegalArgumentException e) {
				throw new ParseException(e.getMessage(), e);
			}
		}
		
		
		// Plain request
		
		// Parse required scope
		v = MultivaluedMapUtils.getFirstValue(params, "scope");
		Scope scope = Scope.parse(v);

		v = MultivaluedMapUtils.getFirstValue(params, "client_notification_token");
		BearerAccessToken clientNotificationToken = null;
		if (StringUtils.isNotBlank(v)) {
			clientNotificationToken = new BearerAccessToken(v);
		}
		
		v = MultivaluedMapUtils.getFirstValue(params, "acr_values");
		List<ACR> acrValues = null;
		if (StringUtils.isNotBlank(v)) {
			acrValues = new LinkedList<>();
			StringTokenizer st = new StringTokenizer(v, " ");
			while (st.hasMoreTokens()) {
				acrValues.add(new ACR(st.nextToken()));
			}
		}
		
		String loginHintTokenString = MultivaluedMapUtils.getFirstValue(params, "login_hint_token");
		
		v = MultivaluedMapUtils.getFirstValue(params, "id_token_hint");
		JWT idTokenHint = null;
		if (StringUtils.isNotBlank(v)) {
			try {
				idTokenHint = JWTParser.parse(v);
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid id_token_hint parameter: " + e.getMessage());
			}
		}
		
		String loginHint = MultivaluedMapUtils.getFirstValue(params, "login_hint");
		
		v = MultivaluedMapUtils.getFirstValue(params, "user_code");
		
		Secret userCode = null;
		if (StringUtils.isNotBlank(v)) {
			userCode = new Secret(v);
		}
		
		String bindingMessage = MultivaluedMapUtils.getFirstValue(params, "binding_message");
		
		v = MultivaluedMapUtils.getFirstValue(params, "requested_expiry");
		
		Integer requestedExpiry = null;
		if (StringUtils.isNotBlank(v)) {
			try {
				requestedExpiry = Integer.valueOf(v);
			} catch (NumberFormatException e) {
				throw new ParseException("The requested_expiry parameter must be an integer");
			}
		}
		
		v = MultivaluedMapUtils.getFirstValue(params, "claims");
		OIDCClaimsRequest claims = null;
		if (StringUtils.isNotBlank(v)) {
			try {
				claims = OIDCClaimsRequest.parse(v);
			} catch (ParseException e) {
				throw new ParseException("Invalid claims parameter: " + e.getMessage(), e);
			}
		}
		
		
		List<LangTag> claimsLocales;
		try {
			claimsLocales = LangTagUtils.parseLangTagList(MultivaluedMapUtils.getFirstValue(params, "claims_locales"));
		} catch (LangTagException e) {
			throw new ParseException("Invalid claims_locales parameter: " + e.getMessage(), e);
		}
		
		String purpose = MultivaluedMapUtils.getFirstValue(params, "purpose");
		
		List<URI> resources = ResourceUtils.parseResourceURIs(params.get("resource"));
		
		// Parse additional custom parameters
		Map<String,List<String>> customParams = null;
		
		for (Map.Entry<String,List<String>> p: params.entrySet()) {
			
			if (! REGISTERED_PARAMETER_NAMES.contains(p.getKey()) && ! clientAuth.getFormParameterNames().contains(p.getKey())) {
				// We have a custom parameter
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				customParams.put(p.getKey(), p.getValue());
			}
		}

		try {
			return new CIBARequest(
				uri, clientAuth,
				scope, clientNotificationToken, acrValues,
				loginHintTokenString, idTokenHint, loginHint,
				bindingMessage, userCode, requestedExpiry,
				claims, claimsLocales, purpose,
				resources,
				customParams);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}

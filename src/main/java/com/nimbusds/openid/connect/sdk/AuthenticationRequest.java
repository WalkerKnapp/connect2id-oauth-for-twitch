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

package com.nimbusds.openid.connect.sdk;


import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.util.*;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.*;


/**
 * OpenID Connect authentication request. Intended to authenticate an end-user
 * and request the end-user's authorisation to release information to the
 * client. Supports custom request parameters.
 *
 * <p>Example HTTP request (code flow):
 *
 * <pre>
 * https://server.example.com/op/authorize?
 * response_type=code%20id_token
 * &amp;client_id=s6BhdRkqt3
 * &amp;redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
 * &amp;scope=openid
 * &amp;nonce=n-0S6_WzA2Mj
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636)
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396)
 *     <li>Resource Indicators for OAuth 2.0 (RFC 8707)
 *     <li>OAuth 2.0 Incremental Authorization (draft-ietf-oauth-incremental-authz)
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) (RFC 9101)
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
 *         (DPoP) (RFC 9449)
 *     <li>OpenID Connect Federation 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public class AuthenticationRequest extends AuthorizationRequest {
	
	
	/**
	 * The purpose string parameter minimal length.
	 */
	public static final int PURPOSE_MIN_LENGTH = 3;
	
	
	/**
	 * The purpose string parameter maximum length.
	 */
	public static final int PURPOSE_MAX_LENGTH = 300;


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	static {
		
		Set<String> p = new HashSet<>(AuthorizationRequest.getRegisteredParameterNames());

		p.add("nonce");
		p.add("display");
		p.add("max_age");
		p.add("ui_locales");
		p.add("claims_locales");
		p.add("id_token_hint");
		p.add("login_hint");
		p.add("acr_values");
		p.add("claims");
		p.add("purpose");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * The nonce (required for implicit flow (unless in JAR), optional for
	 * code flow).
	 */
	private final Nonce nonce;
	
	
	/**
	 * The requested display type (optional).
	 */
	private final Display display;
	
	
	/**
	 * The required maximum authentication age, in seconds, -1 if not
	 * specified, zero implies prompt=login (optional).
	 */
	private final int maxAge;


	/**
	 * The end-user's preferred languages and scripts for the user 
	 * interface (optional).
	 */
	private final List<LangTag> uiLocales;


	/**
	 * The end-user's preferred languages and scripts for claims being 
	 * returned (optional).
	 */
	private final List<LangTag> claimsLocales;


	/**
	 * Previously issued ID Token passed to the authorisation server as a 
	 * hint about the end-user's current or past authenticated session with
	 * the client (optional). Should be present when {@code prompt=none} is 
	 * used.
	 */
	private final JWT idTokenHint;


	/**
	 * Hint to the authorisation server about the login identifier the 
	 * end-user may use to log in (optional).
	 */
	private final String loginHint;


	/**
	 * Requested Authentication Context Class Reference values (optional).
	 */
	private final List<ACR> acrValues;


	/**
	 * Individual claims to be returned (optional).
	 */
	private final OIDCClaimsRequest claims;
	
	
	/**
	 * The transaction specific purpose, for use in OpenID Connect Identity
	 * Assurance (optional).
	 */
	private final String purpose;


	/**
	 * Builder for constructing OpenID Connect authentication requests.
	 */
	public static class Builder {


		/**
		 * The endpoint URI (optional).
		 */
		private URI endpoint;


		/**
		 * The response type (required unless in JAR).
		 */
		private ResponseType rt;


		/**
		 * The client identifier (required unless in JAR).
		 */
		private final ClientID clientID;


		/**
		 * The redirection URI where the response will be sent
		 * (required unless in JAR).
		 */
		private URI redirectURI;


		/**
		 * The scope (required unless in JAR).
		 */
		private Scope scope;


		/**
		 * The opaque value to maintain state between the request and
		 * the callback (recommended).
		 */
		private State state;


		/**
		 * The nonce (required for implicit flow (unless in JAR),
		 * optional for code flow).
		 */
		private Nonce nonce;


		/**
		 * The requested display type (optional).
		 */
		private Display display;


		/**
		 * The requested prompt (optional).
		 */
		private Prompt prompt;
		
		
		/**
		 * The DPoP JWK SHA-256 thumbprint (optional).
		 */
		private JWKThumbprintConfirmation dpopJKT;
		
		
		/**
		 * The OpenID Connect Federation 1.0 trust chain (optional).
		 */
		private TrustChain trustChain;


		/**
		 * The required maximum authentication age, in seconds, -1 if
		 * not specified, zero implies prompt=login (optional).
		 */
		private int maxAge = -1;


		/**
		 * The end-user's preferred languages and scripts for the user
		 * interface (optional).
		 */
		private List<LangTag> uiLocales;


		/**
		 * The end-user's preferred languages and scripts for claims
		 * being returned (optional).
		 */
		private List<LangTag> claimsLocales;


		/**
		 * Previously issued ID Token passed to the authorisation
		 * server as a hint about the end-user's current or past
		 * authenticated session with the client (optional). Should be
		 * present when {@code prompt=none} is used.
		 */
		private JWT idTokenHint;


		/**
		 * Hint to the authorisation server about the login identifier
		 * the end-user may use to log in (optional).
		 */
		private String loginHint;


		/**
		 * Requested Authentication Context Class Reference values
		 * (optional).
		 */
		private List<ACR> acrValues;


		/**
		 * Individual claims to be returned (optional).
		 */
		private OIDCClaimsRequest claims;
		
		
		/**
		 * The transaction specific purpose (optional).
		 */
		private String purpose;


		/**
		 * Request object (optional).
		 */
		private JWT requestObject;


		/**
		 * Request object URI (optional).
		 */
		private URI requestURI;


		/**
		 * The response mode (optional).
		 */
		private ResponseMode rm;


		/**
		 * The authorisation code challenge for PKCE (optional).
		 */
		private CodeChallenge codeChallenge;


		/**
		 * The authorisation code challenge method for PKCE (optional).
		 */
		private CodeChallengeMethod codeChallengeMethod;


		/**
		 * The RAR details (optional).
		 */
		private List<AuthorizationDetail> authorizationDetails;
		
		
		/**
		 * The resource URI(s) (optional).
		 */
		private List<URI> resources;
		
		
		/**
		 * Indicates incremental authorisation (optional).
		 */
		private boolean includeGrantedScopes;


		/**
		 * Custom parameters.
		 */
		private final Map<String,List<String>> customParams = new HashMap<>();


		/**
		 * Creates a new OpenID Connect authentication request builder.
		 *
		 * @param rt          The response type. Corresponds to the
		 *                    {@code response_type} parameter. Must
		 *                    specify a valid OpenID Connect response
		 *                    type. Must not be {@code null}.
		 * @param scope       The request scope. Corresponds to the
		 *                    {@code scope} parameter. Must contain an
		 *                    {@link OIDCScopeValue#OPENID openid
		 *                    value}. Must not be {@code null}.
		 * @param clientID    The client identifier. Corresponds to the
		 *                    {@code client_id} parameter. Must not be
		 *                    {@code null}.
		 * @param redirectURI The redirection URI. Corresponds to the
		 *                    {@code redirect_uri} parameter. Must not
		 *                    be {@code null} unless set by means of
		 *                    the optional {@code request_object} /
		 *                    {@code request_uri} parameter.
		 */
		public Builder(final ResponseType rt,
			       final Scope scope,
			       final ClientID clientID,
			       final URI redirectURI) {

			if (rt == null)
				throw new IllegalArgumentException("The response type must not be null");

			OIDCResponseTypeValidator.validate(rt);

			this.rt = rt;

			if (scope == null)
				throw new IllegalArgumentException("The scope must not be null");

			if (! scope.contains(OIDCScopeValue.OPENID))
				throw new IllegalArgumentException("The scope must include an \"openid\" value");

			this.scope = scope;

			this.clientID = Objects.requireNonNull(clientID);

			// Check presence at build time
			this.redirectURI = redirectURI;
		}


		/**
		 * Creates a new JWT secured OpenID Connect authentication
		 * request (JAR) builder.
		 *
		 * @param requestObject The request object. Must not be
		 *                      {@code null}.
		 * @param clientID      The client ID. Must not be
		 *                      {@code null}.
		 */
		public Builder(final JWT requestObject, final ClientID clientID) {
			
			this.requestObject = Objects.requireNonNull(requestObject);
			this.clientID = Objects.requireNonNull(clientID);
		}


		/**
		 * Creates a new JWT secured OpenID Connect authentication
		 * request (JAR) builder.
		 *
		 * @param requestURI The request object URI. Must not be
		 *                   {@code null}.
		 * @param clientID   The client ID. Must not be {@code null}.
		 */
		public Builder(final URI requestURI, final ClientID clientID) {
			
			this.requestURI = Objects.requireNonNull(requestURI);
			this.clientID = Objects.requireNonNull(clientID);
		}
		
		
		/**
		 * Creates a new OpenID Connect authentication request builder
		 * from the specified request.
		 *
		 * @param request The OpenID Connect authentication request.
		 *                Must not be {@code null}.
		 */
		public Builder(final AuthenticationRequest request) {
			endpoint = request.getEndpointURI();
			rt = request.getResponseType();
			clientID = request.getClientID();
			redirectURI = request.getRedirectionURI();
			scope = request.getScope();
			state = request.getState();
			nonce = request.getNonce();
			display = request.getDisplay();
			prompt = request.getPrompt();
			dpopJKT = request.getDPoPJWKThumbprintConfirmation();
			trustChain = request.getTrustChain();
			maxAge = request.getMaxAge();
			uiLocales = request.getUILocales();
			claimsLocales = request.getClaimsLocales();
			idTokenHint = request.getIDTokenHint();
			loginHint = request.getLoginHint();
			acrValues = request.getACRValues();
			claims = request.getOIDCClaims();
			purpose = request.getPurpose();
			requestObject = request.getRequestObject();
			requestURI = request.getRequestURI();
			rm = request.getResponseMode();
			codeChallenge = request.getCodeChallenge();
			codeChallengeMethod = request.getCodeChallengeMethod();
			authorizationDetails = request.getAuthorizationDetails();
			resources = request.getResources();
			includeGrantedScopes = request.includeGrantedScopes();
			customParams.putAll(request.getCustomParameters());
		}
		
		
		/**
		 * Sets the response type. Corresponds to the
		 * {@code response_type} parameter.
		 *
		 * @param rt The response type. Must not be {@code null}.
		 *
		 * @return This builder.
		 */
		public Builder responseType(final ResponseType rt) {
			
			if (rt == null)
				throw new IllegalArgumentException("The response type must not be null");
			
			this.rt = rt;
			return this;
		}
		
		
		/**
		 * Sets the scope. Corresponds to the {@code scope} parameter.
		 *
		 * @param scope The scope. Must not be {@code null}.
		 *
		 * @return This builder.
		 */
		public Builder scope(final Scope scope) {
			
			if (scope == null)
				throw new IllegalArgumentException("The scope must not be null");
			
			if (! scope.contains(OIDCScopeValue.OPENID))
				throw new IllegalArgumentException("The scope must include an openid value");
			
			this.scope = scope;
			return this;
		}
		
		
		/**
		 * Sets the redirection URI. Corresponds to the
		 * {@code redirection_uri} parameter.
		 *
		 * @param redirectURI The redirection URI. Must not be
		 *                    {@code null}.
		 *
		 * @return This builder.
		 */
		public Builder redirectionURI(final URI redirectURI) {
			
			if (redirectURI == null)
				throw new IllegalArgumentException("The redirection URI must not be null");
			
			this.redirectURI = redirectURI;
			return this;
		}


		/**
		 * Sets the state. Corresponds to the recommended {@code state}
		 * parameter.
		 *
		 * @param state The state, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder state(final State state) {
			this.state = state;
			return this;
		}


		/**
		 * Sets the URI of the authorisation endpoint.
		 *
		 * @param endpoint The URI of the authorisation endpoint. May
		 *                 be {@code null} if the request is not going
		 *                 to be serialised.
		 *
		 * @return This builder.
		 */
		public Builder endpointURI(final URI endpoint) {
			this.endpoint = endpoint;
			return this;
		}


		/**
		 * Sets the nonce. Corresponds to the conditionally optional
		 * {@code nonce} parameter.
		 *
		 * @param nonce The nonce, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder nonce(final Nonce nonce) {
			this.nonce = nonce;
			return this;
		}


		/**
		 * Sets the requested display type. Corresponds to the optional
		 * {@code display} parameter.
		 *
		 * @param display The requested display type, {@code null} if
		 *                not specified.
		 *
		 * @return This builder.
		 */
		public Builder display(final Display display) {
			this.display = display;
			return this;
		}


		/**
		 * Sets the requested prompt. Corresponds to the optional
		 * {@code prompt} parameter.
		 *
		 * @param prompt The requested prompt, {@code null} if not
		 *               specified.
		 *
		 * @return This builder.
		 */
		public Builder prompt(final Prompt prompt) {
			this.prompt = prompt;
			return this;
		}
		
		
		/**
		 * Sets the requested prompt. Corresponds to the optional
		 * {@code prompt} parameter.
		 *
		 * @param promptType The requested prompt types, {@code null}
		 *                   if not specified.
		 *
		 * @return This builder.
		 */
		public Builder prompt(final Prompt.Type ... promptType) {
			if (promptType.length == 1 && promptType[0] == null) {
				return prompt((Prompt)null);
			} else {
				return prompt(new Prompt(promptType));
			}
		}
		
		
		/**
		 * Sets the DPoP JWK SHA-256 thumbprint. Corresponds to the
		 * optional {@code dpop_jkt} parameter.
		 *
		 * @param dpopJKT DPoP JWK SHA-256 thumbprint, {@code null} if
		 *                not specified.
		 *
		 * @return This builder.
		 */
		public Builder dPoPJWKThumbprintConfirmation(final JWKThumbprintConfirmation dpopJKT) {
			this.dpopJKT = dpopJKT;
			return this;
		}
		
		
		/**
		 * Sets the OpenID Connect Federation 1.0 trust chain.
		 * Corresponds to the optional {@code trust_chain} parameter.
		 *
		 * @param trustChain The trust chain, {@code null} if not
		 *                   specified.
		 *
		 * @return This builder.
		 */
		public Builder trustChain(final TrustChain trustChain) {
			this.trustChain = trustChain;
			return this;
		}


		/**
		 * Sets the required maximum authentication age. Corresponds to
		 * the optional {@code max_age} parameter.
		 *
		 * @param maxAge The maximum authentication age, in seconds; 0
		 *               if not specified.
		 *
		 * @return This builder.
		 */
		public Builder maxAge(final int maxAge) {
			this.maxAge = maxAge;
			return this;
		}


		/**
		 * Sets the end-user's preferred languages and scripts for the
		 * user interface, ordered by preference. Corresponds to the
		 * optional {@code ui_locales} parameter.
		 *
		 * @param uiLocales The preferred UI locales, {@code null} if
		 *                  not specified.
		 *
		 * @return This builder.
		 */
		public Builder uiLocales(final List<LangTag> uiLocales) {
			this.uiLocales = uiLocales;
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
		 * Sets the ID Token hint. Corresponds to the conditionally
		 * optional {@code id_token_hint} parameter.
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
		 * Sets the login hint. Corresponds to the optional
		 * {@code login_hint} parameter.
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
		 * Sets the individual claims to be returned. Corresponds to
		 * the optional {@code claims} parameter.
		 *
		 * @see #claims(OIDCClaimsRequest)
		 *
		 * @param claims The individual claims to be returned,
		 *               {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		@Deprecated
		public Builder claims(final ClaimsRequest claims) {

			if (claims == null) {
				this.claims = null;
			} else {
				try {
					this.claims = OIDCClaimsRequest.parse(claims.toJSONObject());
				} catch (ParseException e) {
					// Should never happen
					throw new IllegalArgumentException("Invalid claims: " + e.getMessage(), e);
				}
			}
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
		 * Sets the request object. Corresponds to the optional
		 * {@code request} parameter. Must not be specified together
		 * with a request object URI.
		 *
		 * @param requestObject The request object, {@code null} if not
		 *                      specified.
		 *
		 * @return This builder.
		 */
		public Builder requestObject(final JWT requestObject) {
			this.requestObject = requestObject;
			return this;
		}


		/**
		 * Sets the request object URI. Corresponds to the optional
		 * {@code request_uri} parameter. Must not be specified
		 * together with a request object.
		 *
		 * @param requestURI The request object URI, {@code null} if
		 *                   not specified.
		 *
		 * @return This builder.
		 */
		public Builder requestURI(final URI requestURI) {
			this.requestURI = requestURI;
			return this;
		}


		/**
		 * Sets the response mode. Corresponds to the optional
		 * {@code response_mode} parameter. Use of this parameter is
		 * not recommended unless a non-default response mode is
		 * requested (e.g. form_post).
		 *
		 * @param rm The response mode, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder responseMode(final ResponseMode rm) {
			this.rm = rm;
			return this;
		}
		
		
		/**
		 * Sets the code challenge for Proof Key for Code Exchange
		 * (PKCE) by public OAuth clients.
		 *
		 * @param codeChallenge       The code challenge, {@code null}
		 *                            if not specified.
		 * @param codeChallengeMethod The code challenge method,
		 *                            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		@Deprecated
		public Builder codeChallenge(final CodeChallenge codeChallenge, final CodeChallengeMethod codeChallengeMethod) {
			this.codeChallenge = codeChallenge;
			this.codeChallengeMethod = codeChallengeMethod;
			return this;
		}
		
		
		/**
		 * Sets the code challenge for Proof Key for Code Exchange
		 * (PKCE) by public OAuth clients.
		 *
		 * @param codeVerifier        The code verifier to use to
		 *                            compute the code challenge,
		 *                            {@code null} if PKCE is not
		 *                            specified.
		 * @param codeChallengeMethod The code challenge method,
		 *                            {@code null} if not specified.
		 *                            Defaults to
		 *                            {@link CodeChallengeMethod#PLAIN}
		 *                            if a code verifier is specified.
		 *
		 * @return This builder.
		 */
		public Builder codeChallenge(final CodeVerifier codeVerifier, final CodeChallengeMethod codeChallengeMethod) {
			if (codeVerifier != null) {
				CodeChallengeMethod method = codeChallengeMethod != null ? codeChallengeMethod : CodeChallengeMethod.getDefault();
				this.codeChallenge = CodeChallenge.compute(method, codeVerifier);
				this.codeChallengeMethod = method;
			} else {
				this.codeChallenge = null;
				this.codeChallengeMethod = null;
			}
			return this;
		}


		/**
		 * Sets the Rich Authorisation Request (RAR) details.
		 *
		 * @param authorizationDetails The authorisation details,
		 *                             {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder authorizationDetails(final List<AuthorizationDetail> authorizationDetails) {
			this.authorizationDetails = authorizationDetails;
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
		 * Requests incremental authorisation.
		 *
		 * @param includeGrantedScopes {@code true} to request
		 *                             incremental authorisation.
		 *
		 * @return This builder.
		 */
		public Builder includeGrantedScopes(final boolean includeGrantedScopes) {
			this.includeGrantedScopes = includeGrantedScopes;
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
		 * Builds a new authentication request.
		 *
		 * @return The authentication request.
		 */
		public AuthenticationRequest build() {

			try {
				return new AuthenticationRequest(
					endpoint, rt, rm, scope, clientID, redirectURI, state, nonce,
					display, prompt, dpopJKT, trustChain, maxAge, uiLocales, claimsLocales,
					idTokenHint, loginHint, acrValues, claims,
					purpose,
					requestObject, requestURI,
					codeChallenge, codeChallengeMethod,
					authorizationDetails,
					resources,
					includeGrantedScopes,
					customParams);

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}
	
	
	/**
	 * Creates a new minimal OpenID Connect authentication request.
	 *
	 * @param endpoint    The URI of the authorisation endpoint. May be
	 *                    {@code null} if the request is not going to be
	 *                    serialised.
	 * @param rt          The response type. Corresponds to the 
	 *                    {@code response_type} parameter. Must specify a
	 *                    valid OpenID Connect response type. Must not be
	 *                    {@code null}.
	 * @param scope       The request scope. Corresponds to the
	 *                    {@code scope} parameter. Must contain an
	 *                    {@link OIDCScopeValue#OPENID openid value}. Must
	 *                    not be {@code null}.
	 * @param clientID    The client identifier. Corresponds to the
	 *                    {@code client_id} parameter. Must not be 
	 *                    {@code null}.
	 * @param redirectURI The redirection URI. Corresponds to the
	 *                    {@code redirect_uri} parameter. Must not be 
	 *                    {@code null}.
	 * @param state       The state. Corresponds to the {@code state}
	 *                    parameter. May be {@code null}.
	 * @param nonce       The nonce. Corresponds to the {@code nonce} 
	 *                    parameter. May be {@code null} for code flow.
	 */
	public AuthenticationRequest(final URI endpoint,
				     final ResponseType rt,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce) {

		// Not specified: display, prompt, maxAge, uiLocales, claimsLocales, 
		// idTokenHint, loginHint, acrValues, claims, purpose
		// codeChallenge, codeChallengeMethod
		this(endpoint, rt, null, scope, clientID, redirectURI, state, nonce,
			null, null, -1, null, null,
			null, null, null, (OIDCClaimsRequest) null, null,
			null, null,
			null, null,
			null, false, null);
	}


	/**
	 * Creates a new OpenID Connect authentication request with extension
	 * and custom parameters.
	 *
	 * @param endpoint             The URI of the authorisation endpoint.
	 *                             May be {@code null} if the request is
	 *                             not going to be serialised.
	 * @param rt                   The response type set. Corresponds to
	 *                             the {@code response_type} parameter.
	 *                             Must specify a valid OpenID Connect
	 *                             response type. Must not be {@code null}.
	 * @param rm                   The response mode. Corresponds to the
	 *                             optional {@code response_mode}
	 *                             parameter. Use of this parameter is not
	 *                             recommended unless a non-default
	 *                             response mode is requested (e.g.
	 *                             form_post).
	 * @param scope                The request scope. Corresponds to the
	 *                             {@code scope} parameter. Must contain an
	 *                             {@link OIDCScopeValue#OPENID openid
	 *                             value}. Must not be {@code null}.
	 * @param clientID             The client identifier. Corresponds to
	 *                             the {@code client_id} parameter. Must
	 *                             not be {@code null}.
	 * @param redirectURI          The redirection URI. Corresponds to the
	 *                             {@code redirect_uri} parameter. Must not
	 *                             be {@code null} unless set by means of
	 *                             the optional {@code request_object} /
	 *                             {@code request_uri} parameter.
	 * @param state                The state. Corresponds to the
	 *                             recommended {@code state} parameter.
	 *                             {@code null} if not specified.
	 * @param nonce                The nonce. Corresponds to the
	 *                             {@code nonce} parameter. May be
	 *                             {@code null} for code flow.
	 * @param display              The requested display type. Corresponds
	 *                             to the optional {@code display}
	 *                             parameter.
	 *                             {@code null} if not specified.
	 * @param prompt               The requested prompt. Corresponds to the
	 *                             optional {@code prompt} parameter.
	 *                             {@code null} if not specified.
	 * @param maxAge               The required maximum authentication age,
	 *                             in seconds. Corresponds to the optional
	 *                             {@code max_age} parameter. -1 if not
	 *                             specified, zero implies
	 *                             {@code prompt=login}.
	 * @param uiLocales            The preferred languages and scripts for
	 *                             the user interface. Corresponds to the
	 *                             optional {@code ui_locales} parameter.
	 *                             {@code null} if not specified.
	 * @param claimsLocales        The preferred languages and scripts for
	 *                             claims being returned. Corresponds to
	 *                             the optional {@code claims_locales}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param idTokenHint          The ID Token hint. Corresponds to the
	 *                             optional {@code id_token_hint}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param loginHint            The login hint. Corresponds to the
	 *                             optional {@code login_hint} parameter.
	 *                             {@code null} if not specified.
	 * @param acrValues            The requested Authentication Context
	 *                             Class Reference values. Corresponds to
	 *                             the optional {@code acr_values}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param claims               The individual claims to be returned.
	 *                             Corresponds to the optional
	 *                             {@code claims} parameter. {@code null}
	 *                             if not specified.
	 * @param purpose              The transaction specific purpose,
	 *                             {@code null} if not specified.
	 * @param requestObject        The request object. Corresponds to the
	 *                             optional {@code request} parameter. Must
	 *                             not be specified together with a request
	 *                             object URI. {@code null} if not
	 *                             specified.
	 * @param requestURI           The request object URI. Corresponds to
	 *                             the optional {@code request_uri}
	 *                             parameter. Must not be specified
	 *                             together with a request object.
	 *                             {@code null} if not specified.
	 * @param codeChallenge        The code challenge for PKCE,
	 *                             {@code null} if not specified.
	 * @param codeChallengeMethod  The code challenge method for PKCE,
	 *                             {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param includeGrantedScopes {@code true} to request incremental
	 *                             authorisation.
	 * @param customParams         Additional custom parameters, empty map
	 *                             or {@code null} if none.
	 */
	@Deprecated
	public AuthenticationRequest(final URI endpoint,
				     final ResponseType rt,
				     final ResponseMode rm,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce,
				     final Display display,
				     final Prompt prompt,
				     final int maxAge,
				     final List<LangTag> uiLocales,
				     final List<LangTag> claimsLocales,
				     final JWT idTokenHint,
				     final String loginHint,
				     final List<ACR> acrValues,
				     final ClaimsRequest claims,
				     final String purpose,
				     final JWT requestObject,
				     final URI requestURI,
				     final CodeChallenge codeChallenge,
				     final CodeChallengeMethod codeChallengeMethod,
				     final List<URI> resources,
				     final boolean includeGrantedScopes,
				     final Map<String,List<String>> customParams) {

		this(endpoint, rt, rm, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, toOIDCClaimsRequestWithSilentFail(claims), purpose,
			requestObject, requestURI,
			codeChallenge, codeChallengeMethod,
			resources, includeGrantedScopes, customParams);
	}

	
	/**
	 * Creates a new OpenID Connect authentication request with extension
	 * and custom parameters.
	 *
	 * @param endpoint             The URI of the authorisation endpoint.
	 *                             May be {@code null} if the request is
	 *                             not going to be serialised.
	 * @param rt                   The response type set. Corresponds to
	 *                             the {@code response_type} parameter.
	 *                             Must specify a valid OpenID Connect
	 *                             response type. Must not be {@code null}.
	 * @param rm                   The response mode. Corresponds to the
	 *                             optional {@code response_mode}
	 *                             parameter. Use of this parameter is not
	 *                             recommended unless a non-default
	 *                             response mode is requested (e.g.
	 *                             form_post).
	 * @param scope                The request scope. Corresponds to the
	 *                             {@code scope} parameter. Must contain an
	 *                             {@link OIDCScopeValue#OPENID openid
	 *                             value}. Must not be {@code null}.
	 * @param clientID             The client identifier. Corresponds to
	 *                             the {@code client_id} parameter. Must
	 *                             not be {@code null}.
	 * @param redirectURI          The redirection URI. Corresponds to the
	 *                             {@code redirect_uri} parameter. Must not
	 *                             be {@code null} unless set by means of
	 *                             the optional {@code request_object} /
	 *                             {@code request_uri} parameter.
	 * @param state                The state. Corresponds to the
	 *                             recommended {@code state} parameter.
	 *                             {@code null} if not specified.
	 * @param nonce                The nonce. Corresponds to the
	 *                             {@code nonce} parameter. May be
	 *                             {@code null} for code flow.
	 * @param display              The requested display type. Corresponds
	 *                             to the optional {@code display}
	 *                             parameter.
	 *                             {@code null} if not specified.
	 * @param prompt               The requested prompt. Corresponds to the
	 *                             optional {@code prompt} parameter.
	 *                             {@code null} if not specified.
	 * @param maxAge               The required maximum authentication age,
	 *                             in seconds. Corresponds to the optional
	 *                             {@code max_age} parameter. -1 if not
	 *                             specified, zero implies
	 *                             {@code prompt=login}.
	 * @param uiLocales            The preferred languages and scripts for
	 *                             the user interface. Corresponds to the
	 *                             optional {@code ui_locales} parameter.
	 *                             {@code null} if not specified.
	 * @param claimsLocales        The preferred languages and scripts for
	 *                             claims being returned. Corresponds to
	 *                             the optional {@code claims_locales}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param idTokenHint          The ID Token hint. Corresponds to the
	 *                             optional {@code id_token_hint}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param loginHint            The login hint. Corresponds to the
	 *                             optional {@code login_hint} parameter.
	 *                             {@code null} if not specified.
	 * @param acrValues            The requested Authentication Context
	 *                             Class Reference values. Corresponds to
	 *                             the optional {@code acr_values}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param claims               The individual OpenID claims to be
	 *                             returned. Corresponds to the optional
	 *                             {@code claims} parameter. {@code null}
	 *                             if not specified.
	 * @param purpose              The transaction specific purpose,
	 *                             {@code null} if not specified.
	 * @param requestObject        The request object. Corresponds to the
	 *                             optional {@code request} parameter. Must
	 *                             not be specified together with a request
	 *                             object URI. {@code null} if not
	 *                             specified.
	 * @param requestURI           The request object URI. Corresponds to
	 *                             the optional {@code request_uri}
	 *                             parameter. Must not be specified
	 *                             together with a request object.
	 *                             {@code null} if not specified.
	 * @param codeChallenge        The code challenge for PKCE,
	 *                             {@code null} if not specified.
	 * @param codeChallengeMethod  The code challenge method for PKCE,
	 *                             {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param includeGrantedScopes {@code true} to request incremental
	 *                             authorisation.
	 * @param customParams         Additional custom parameters, empty map
	 *                             or {@code null} if none.
	 */
	@Deprecated
	public AuthenticationRequest(final URI endpoint,
				     final ResponseType rt,
				     final ResponseMode rm,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce,
				     final Display display,
				     final Prompt prompt,
				     final int maxAge,
				     final List<LangTag> uiLocales,
				     final List<LangTag> claimsLocales,
				     final JWT idTokenHint,
				     final String loginHint,
				     final List<ACR> acrValues,
				     final OIDCClaimsRequest claims,
				     final String purpose,
				     final JWT requestObject,
				     final URI requestURI,
				     final CodeChallenge codeChallenge,
				     final CodeChallengeMethod codeChallengeMethod,
				     final List<URI> resources,
				     final boolean includeGrantedScopes,
				     final Map<String,List<String>> customParams) {

		this(endpoint, rt, rm, scope, clientID, redirectURI, state, nonce, display, prompt, null, null,
			maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues, claims, purpose,
			requestObject, requestURI, codeChallenge, codeChallengeMethod,
			resources, includeGrantedScopes,
			customParams);
	}

	
	/**
	 * Creates a new OpenID Connect authentication request with extension
	 * and custom parameters.
	 *
	 * @param endpoint             The URI of the authorisation endpoint.
	 *                             May be {@code null} if the request is
	 *                             not going to be serialised.
	 * @param rt                   The response type set. Corresponds to
	 *                             the {@code response_type} parameter.
	 *                             Must specify a valid OpenID Connect
	 *                             response type. Must not be {@code null}.
	 * @param rm                   The response mode. Corresponds to the
	 *                             optional {@code response_mode}
	 *                             parameter. Use of this parameter is not
	 *                             recommended unless a non-default
	 *                             response mode is requested (e.g.
	 *                             form_post).
	 * @param scope                The request scope. Corresponds to the
	 *                             {@code scope} parameter. Must contain an
	 *                             {@link OIDCScopeValue#OPENID openid
	 *                             value}. Must not be {@code null}.
	 * @param clientID             The client identifier. Corresponds to
	 *                             the {@code client_id} parameter. Must
	 *                             not be {@code null}.
	 * @param redirectURI          The redirection URI. Corresponds to the
	 *                             {@code redirect_uri} parameter. Must not
	 *                             be {@code null} unless set by means of
	 *                             the optional {@code request_object} /
	 *                             {@code request_uri} parameter.
	 * @param state                The state. Corresponds to the
	 *                             recommended {@code state} parameter.
	 *                             {@code null} if not specified.
	 * @param nonce                The nonce. Corresponds to the
	 *                             {@code nonce} parameter. May be
	 *                             {@code null} for code flow.
	 * @param display              The requested display type. Corresponds
	 *                             to the optional {@code display}
	 *                             parameter.
	 *                             {@code null} if not specified.
	 * @param prompt               The requested prompt. Corresponds to the
	 *                             optional {@code prompt} parameter.
	 *                             {@code null} if not specified.
	 * @param dpopJKT              The DPoP JWK SHA-256 thumbprint,
	 *                             {@code null} if not specified.
	 * @param maxAge               The required maximum authentication age,
	 *                             in seconds. Corresponds to the optional
	 *                             {@code max_age} parameter. -1 if not
	 *                             specified, zero implies
	 *                             {@code prompt=login}.
	 * @param uiLocales            The preferred languages and scripts for
	 *                             the user interface. Corresponds to the
	 *                             optional {@code ui_locales} parameter.
	 *                             {@code null} if not specified.
	 * @param claimsLocales        The preferred languages and scripts for
	 *                             claims being returned. Corresponds to
	 *                             the optional {@code claims_locales}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param idTokenHint          The ID Token hint. Corresponds to the
	 *                             optional {@code id_token_hint}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param loginHint            The login hint. Corresponds to the
	 *                             optional {@code login_hint} parameter.
	 *                             {@code null} if not specified.
	 * @param acrValues            The requested Authentication Context
	 *                             Class Reference values. Corresponds to
	 *                             the optional {@code acr_values}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param claims               The individual OpenID claims to be
	 *                             returned. Corresponds to the optional
	 *                             {@code claims} parameter. {@code null}
	 *                             if not specified.
	 * @param purpose              The transaction specific purpose,
	 *                             {@code null} if not specified.
	 * @param requestObject        The request object. Corresponds to the
	 *                             optional {@code request} parameter. Must
	 *                             not be specified together with a request
	 *                             object URI. {@code null} if not
	 *                             specified.
	 * @param requestURI           The request object URI. Corresponds to
	 *                             the optional {@code request_uri}
	 *                             parameter. Must not be specified
	 *                             together with a request object.
	 *                             {@code null} if not specified.
	 * @param codeChallenge        The code challenge for PKCE,
	 *                             {@code null} if not specified.
	 * @param codeChallengeMethod  The code challenge method for PKCE,
	 *                             {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param includeGrantedScopes {@code true} to request incremental
	 *                             authorisation.
	 * @param customParams         Additional custom parameters, empty map
	 *                             or {@code null} if none.
	 */
	@Deprecated
	public AuthenticationRequest(final URI endpoint,
				     final ResponseType rt,
				     final ResponseMode rm,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce,
				     final Display display,
				     final Prompt prompt,
				     final JWKThumbprintConfirmation dpopJKT,
				     final int maxAge,
				     final List<LangTag> uiLocales,
				     final List<LangTag> claimsLocales,
				     final JWT idTokenHint,
				     final String loginHint,
				     final List<ACR> acrValues,
				     final OIDCClaimsRequest claims,
				     final String purpose,
				     final JWT requestObject,
				     final URI requestURI,
				     final CodeChallenge codeChallenge,
				     final CodeChallengeMethod codeChallengeMethod,
				     final List<URI> resources,
				     final boolean includeGrantedScopes,
				     final Map<String,List<String>> customParams) {
		
		this(endpoint, rt, rm, scope, clientID, redirectURI, state, nonce, display, prompt, dpopJKT, null,
			maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues, claims, purpose,
			requestObject, requestURI, codeChallenge, codeChallengeMethod,
			resources, includeGrantedScopes,
			customParams);
	}

	
	/**
	 * Creates a new OpenID Connect authentication request with extension
	 * and custom parameters.
	 *
	 * @param endpoint             The URI of the authorisation endpoint.
	 *                             May be {@code null} if the request is
	 *                             not going to be serialised.
	 * @param rt                   The response type set. Corresponds to
	 *                             the {@code response_type} parameter.
	 *                             Must specify a valid OpenID Connect
	 *                             response type. Must not be {@code null}.
	 * @param rm                   The response mode. Corresponds to the
	 *                             optional {@code response_mode}
	 *                             parameter. Use of this parameter is not
	 *                             recommended unless a non-default
	 *                             response mode is requested (e.g.
	 *                             form_post).
	 * @param scope                The request scope. Corresponds to the
	 *                             {@code scope} parameter. Must contain an
	 *                             {@link OIDCScopeValue#OPENID openid
	 *                             value}. Must not be {@code null}.
	 * @param clientID             The client identifier. Corresponds to
	 *                             the {@code client_id} parameter. Must
	 *                             not be {@code null}.
	 * @param redirectURI          The redirection URI. Corresponds to the
	 *                             {@code redirect_uri} parameter. Must not
	 *                             be {@code null} unless set by means of
	 *                             the optional {@code request_object} /
	 *                             {@code request_uri} parameter.
	 * @param state                The state. Corresponds to the
	 *                             recommended {@code state} parameter.
	 *                             {@code null} if not specified.
	 * @param nonce                The nonce. Corresponds to the
	 *                             {@code nonce} parameter. May be
	 *                             {@code null} for code flow.
	 * @param display              The requested display type. Corresponds
	 *                             to the optional {@code display}
	 *                             parameter.
	 *                             {@code null} if not specified.
	 * @param prompt               The requested prompt. Corresponds to the
	 *                             optional {@code prompt} parameter.
	 *                             {@code null} if not specified.
	 * @param dpopJKT              The DPoP JWK SHA-256 thumbprint,
	 *                             {@code null} if not specified.
	 * @param trustChain           The OpenID Connect Federation 1.0 trust
	 *                             chain, {@code null} if not specified.
	 * @param maxAge               The required maximum authentication age,
	 *                             in seconds. Corresponds to the optional
	 *                             {@code max_age} parameter. -1 if not
	 *                             specified, zero implies
	 *                             {@code prompt=login}.
	 * @param uiLocales            The preferred languages and scripts for
	 *                             the user interface. Corresponds to the
	 *                             optional {@code ui_locales} parameter.
	 *                             {@code null} if not specified.
	 * @param claimsLocales        The preferred languages and scripts for
	 *                             claims being returned. Corresponds to
	 *                             the optional {@code claims_locales}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param idTokenHint          The ID Token hint. Corresponds to the
	 *                             optional {@code id_token_hint}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param loginHint            The login hint. Corresponds to the
	 *                             optional {@code login_hint} parameter.
	 *                             {@code null} if not specified.
	 * @param acrValues            The requested Authentication Context
	 *                             Class Reference values. Corresponds to
	 *                             the optional {@code acr_values}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param claims               The individual OpenID claims to be
	 *                             returned. Corresponds to the optional
	 *                             {@code claims} parameter. {@code null}
	 *                             if not specified.
	 * @param purpose              The transaction specific purpose,
	 *                             {@code null} if not specified.
	 * @param requestObject        The request object. Corresponds to the
	 *                             optional {@code request} parameter. Must
	 *                             not be specified together with a request
	 *                             object URI. {@code null} if not
	 *                             specified.
	 * @param requestURI           The request object URI. Corresponds to
	 *                             the optional {@code request_uri}
	 *                             parameter. Must not be specified
	 *                             together with a request object.
	 *                             {@code null} if not specified.
	 * @param codeChallenge        The code challenge for PKCE,
	 *                             {@code null} if not specified.
	 * @param codeChallengeMethod  The code challenge method for PKCE,
	 *                             {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param includeGrantedScopes {@code true} to request incremental
	 *                             authorisation.
	 * @param customParams         Additional custom parameters, empty map
	 *                             or {@code null} if none.
	 */
	@Deprecated
	public AuthenticationRequest(final URI endpoint,
				     final ResponseType rt,
				     final ResponseMode rm,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce,
				     final Display display,
				     final Prompt prompt,
				     final JWKThumbprintConfirmation dpopJKT,
				     final TrustChain trustChain,
				     final int maxAge,
				     final List<LangTag> uiLocales,
				     final List<LangTag> claimsLocales,
				     final JWT idTokenHint,
				     final String loginHint,
				     final List<ACR> acrValues,
				     final OIDCClaimsRequest claims,
				     final String purpose,
				     final JWT requestObject,
				     final URI requestURI,
				     final CodeChallenge codeChallenge,
				     final CodeChallengeMethod codeChallengeMethod,
				     final List<URI> resources,
				     final boolean includeGrantedScopes,
				     final Map<String,List<String>> customParams) {

		this(endpoint, rt, rm, scope, clientID, redirectURI, state, nonce, display, prompt,
			dpopJKT, trustChain,
			maxAge, uiLocales, claimsLocales, idTokenHint, loginHint, acrValues, claims, purpose,
			requestObject, requestURI,
			codeChallenge, codeChallengeMethod,
			null, resources, includeGrantedScopes,
			customParams);
	}


	/**
	 * Creates a new OpenID Connect authentication request with extension
	 * and custom parameters.
	 *
	 * @param endpoint             The URI of the authorisation endpoint.
	 *                             May be {@code null} if the request is
	 *                             not going to be serialised.
	 * @param rt                   The response type set. Corresponds to
	 *                             the {@code response_type} parameter.
	 *                             Must specify a valid OpenID Connect
	 *                             response type. Must not be {@code null}.
	 * @param rm                   The response mode. Corresponds to the
	 *                             optional {@code response_mode}
	 *                             parameter. Use of this parameter is not
	 *                             recommended unless a non-default
	 *                             response mode is requested (e.g.
	 *                             form_post).
	 * @param scope                The request scope. Corresponds to the
	 *                             {@code scope} parameter. Must contain an
	 *                             {@link OIDCScopeValue#OPENID openid
	 *                             value}. Must not be {@code null}.
	 * @param clientID             The client identifier. Corresponds to
	 *                             the {@code client_id} parameter. Must
	 *                             not be {@code null}.
	 * @param redirectURI          The redirection URI. Corresponds to the
	 *                             {@code redirect_uri} parameter. Must not
	 *                             be {@code null} unless set by means of
	 *                             the optional {@code request_object} /
	 *                             {@code request_uri} parameter.
	 * @param state                The state. Corresponds to the
	 *                             recommended {@code state} parameter.
	 *                             {@code null} if not specified.
	 * @param nonce                The nonce. Corresponds to the
	 *                             {@code nonce} parameter. May be
	 *                             {@code null} for code flow.
	 * @param display              The requested display type. Corresponds
	 *                             to the optional {@code display}
	 *                             parameter.
	 *                             {@code null} if not specified.
	 * @param prompt               The requested prompt. Corresponds to the
	 *                             optional {@code prompt} parameter.
	 *                             {@code null} if not specified.
	 * @param dpopJKT              The DPoP JWK SHA-256 thumbprint,
	 *                             {@code null} if not specified.
	 * @param trustChain           The OpenID Connect Federation 1.0 trust
	 *                             chain, {@code null} if not specified.
	 * @param maxAge               The required maximum authentication age,
	 *                             in seconds. Corresponds to the optional
	 *                             {@code max_age} parameter. -1 if not
	 *                             specified, zero implies
	 *                             {@code prompt=login}.
	 * @param uiLocales            The preferred languages and scripts for
	 *                             the user interface. Corresponds to the
	 *                             optional {@code ui_locales} parameter.
	 *                             {@code null} if not specified.
	 * @param claimsLocales        The preferred languages and scripts for
	 *                             claims being returned. Corresponds to
	 *                             the optional {@code claims_locales}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param idTokenHint          The ID Token hint. Corresponds to the
	 *                             optional {@code id_token_hint}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param loginHint            The login hint. Corresponds to the
	 *                             optional {@code login_hint} parameter.
	 *                             {@code null} if not specified.
	 * @param acrValues            The requested Authentication Context
	 *                             Class Reference values. Corresponds to
	 *                             the optional {@code acr_values}
	 *                             parameter. {@code null} if not
	 *                             specified.
	 * @param claims               The individual OpenID claims to be
	 *                             returned. Corresponds to the optional
	 *                             {@code claims} parameter. {@code null}
	 *                             if not specified.
	 * @param purpose              The transaction specific purpose,
	 *                             {@code null} if not specified.
	 * @param requestObject        The request object. Corresponds to the
	 *                             optional {@code request} parameter. Must
	 *                             not be specified together with a request
	 *                             object URI. {@code null} if not
	 *                             specified.
	 * @param requestURI           The request object URI. Corresponds to
	 *                             the optional {@code request_uri}
	 *                             parameter. Must not be specified
	 *                             together with a request object.
	 *                             {@code null} if not specified.
	 * @param codeChallenge        The code challenge for PKCE,
	 *                             {@code null} if not specified.
	 * @param codeChallengeMethod  The code challenge method for PKCE,
	 *                             {@code null} if not specified.
	 * @param authorizationDetails The authorisation details,
	 *                             {@code null} if not specified.
	 * @param resources            The resource URI(s), {@code null} if not
	 *                             specified.
	 * @param includeGrantedScopes {@code true} to request incremental
	 *                             authorisation.
	 * @param customParams         Additional custom parameters, empty map
	 *                             or {@code null} if none.
	 */
	public AuthenticationRequest(final URI endpoint,
				     final ResponseType rt,
				     final ResponseMode rm,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce,
				     final Display display,
				     final Prompt prompt,
				     final JWKThumbprintConfirmation dpopJKT,
				     final TrustChain trustChain,
				     final int maxAge,
				     final List<LangTag> uiLocales,
				     final List<LangTag> claimsLocales,
				     final JWT idTokenHint,
				     final String loginHint,
				     final List<ACR> acrValues,
				     final OIDCClaimsRequest claims,
				     final String purpose,
				     final JWT requestObject,
				     final URI requestURI,
				     final CodeChallenge codeChallenge,
				     final CodeChallengeMethod codeChallengeMethod,
				     final List<AuthorizationDetail> authorizationDetails,
				     final List<URI> resources,
				     final boolean includeGrantedScopes,
				     final Map<String,List<String>> customParams) {

		super(endpoint, rt, rm, clientID, redirectURI, scope, state,
			codeChallenge, codeChallengeMethod,
			authorizationDetails, resources, includeGrantedScopes,
			requestObject, requestURI, prompt, dpopJKT, trustChain, customParams);

		if (! specifiesRequestObject()) {

			// Check parameters required by OpenID Connect if no JAR

			if (redirectURI == null)
				throw new IllegalArgumentException("The redirection URI must not be null");

			OIDCResponseTypeValidator.validate(rt);

			if (scope == null)
				throw new IllegalArgumentException("The scope must not be null");

			if (!scope.contains(OIDCScopeValue.OPENID))
				throw new IllegalArgumentException("The scope must include an \"openid\" value");

			// Check nonce requirement
			if (nonce == null && Nonce.isRequired(rt)) {
				throw new IllegalArgumentException("Nonce required for response_type=" + rt);
			}
		}

		this.nonce = nonce;

		// Optional parameters
		this.display = display;
		this.maxAge = maxAge;

		if (uiLocales != null)
			this.uiLocales = Collections.unmodifiableList(uiLocales);
		else
			this.uiLocales = null;

		if (claimsLocales != null)
			this.claimsLocales = Collections.unmodifiableList(claimsLocales);
		else
			this.claimsLocales = null;

		this.idTokenHint = idTokenHint;
		this.loginHint = loginHint;

		if (acrValues != null)
			this.acrValues = Collections.unmodifiableList(acrValues);
		else
			this.acrValues = null;

		this.claims = claims;

		if (purpose != null) {
			if (purpose.length() < PURPOSE_MIN_LENGTH) {
				throw new IllegalArgumentException("The purpose must not be shorter than " + PURPOSE_MIN_LENGTH + " characters");
			}
			if (purpose.length() > PURPOSE_MAX_LENGTH) {
				throw new IllegalArgumentException("The purpose must not be longer than " + PURPOSE_MAX_LENGTH +" characters");
			}
		}

		this.purpose = purpose;
	}


	/**
	 * Returns the registered (standard) OpenID Connect authentication
	 * request parameter names.
	 *
	 * @return The registered OpenID Connect authentication request
	 *         parameter names, as a unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}
	
	
	/**
	 * Returns the nonce. Corresponds to the conditionally optional 
	 * {@code nonce} parameter.
	 *
	 * @return The nonce, {@code null} if not specified.
	 */
	public Nonce getNonce() {
	
		return nonce;
	}
	
	
	/**
	 * Returns the requested display type. Corresponds to the optional
	 * {@code display} parameter.
	 *
	 * @return The requested display type, {@code null} if not specified.
	 */
	public Display getDisplay() {
	
		return display;
	}
	
	
	/**
	 * Returns the required maximum authentication age. Corresponds to the
	 * optional {@code max_age} parameter.
	 *
	 * @return The maximum authentication age, in seconds; -1 if not
	 *         specified, zero implies {@code prompt=login}.
	 */
	public int getMaxAge() {
	
		return maxAge;
	}


	/**
	 * Returns the end-user's preferred languages and scripts for the user
	 * interface, ordered by preference. Corresponds to the optional
	 * {@code ui_locales} parameter.
	 *
	 * @return The preferred UI locales, {@code null} if not specified.
	 */
	public List<LangTag> getUILocales() {

		return uiLocales;
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
	 * Returns the ID Token hint. Corresponds to the conditionally optional 
	 * {@code id_token_hint} parameter.
	 *
	 * @return The ID Token hint, {@code null} if not specified.
	 */
	public JWT getIDTokenHint() {
	
		return idTokenHint;
	}


	/**
	 * Returns the login hint. Corresponds to the optional {@code login_hint} 
	 * parameter.
	 *
	 * @return The login hint, {@code null} if not specified.
	 */
	public String getLoginHint() {

		return loginHint;
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
	 * Returns the individual claims to be returned. Corresponds to the 
	 * optional {@code claims} parameter.
	 *
	 * @see #getOIDCClaims()
	 *
	 * @return The individual claims to be returned, {@code null} if not
	 *         specified.
	 */
	@Deprecated
	public ClaimsRequest getClaims() {

		return toClaimsRequestWithSilentFail(claims);
	}
	
	
	private static OIDCClaimsRequest toOIDCClaimsRequestWithSilentFail(final ClaimsRequest claims) {
		if (claims == null) {
			return null;
		}
		try {
			return OIDCClaimsRequest.parse(claims.toJSONObject());
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	private static ClaimsRequest toClaimsRequestWithSilentFail(final OIDCClaimsRequest claims) {
		if (claims == null) {
			return null;
		}
		try {
			return ClaimsRequest.parse(claims.toJSONObject());
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the individual OpenID claims to be returned. Corresponds to
	 * the optional {@code claims} parameter.
	 *
	 * @return The individual claims to be returned, {@code null} if not
	 *         specified.
	 */
	public OIDCClaimsRequest getOIDCClaims() {

		return claims;
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


	@Override
	public Map<String,List<String>> toParameters() {

		Map <String,List<String>> params = super.toParameters();
		
		if (nonce != null)
			params.put("nonce", Collections.singletonList(nonce.toString()));
		
		if (display != null)
			params.put("display", Collections.singletonList(display.toString()));

		if (maxAge >= 0)
			params.put("max_age", Collections.singletonList("" + maxAge));

		if (uiLocales != null) {
			params.put("ui_locales", Collections.singletonList(LangTagUtils.concat(uiLocales)));
		}

		if (CollectionUtils.isNotEmpty(claimsLocales)) {
			params.put("claims_locales", Collections.singletonList(LangTagUtils.concat(claimsLocales)));
		}

		if (idTokenHint != null) {
		
			try {
				params.put("id_token_hint", Collections.singletonList(idTokenHint.serialize()));
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize ID token hint: " + e.getMessage(), e);
			}
		}

		if (loginHint != null)
			params.put("login_hint", Collections.singletonList(loginHint));

		if (acrValues != null) {

			StringBuilder sb = new StringBuilder();

			for (ACR acr: acrValues) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(acr.toString());
			}

			params.put("acr_values", Collections.singletonList(sb.toString()));
		}
			

		if (claims != null)
			params.put("claims", Collections.singletonList(claims.toJSONObject().toString()));
		
		if (purpose != null)
			params.put("purpose", Collections.singletonList(purpose));

		return params;
	}
	
	
	@Override
	public JWTClaimsSet toJWTClaimsSet() {
		
		JWTClaimsSet jwtClaimsSet = super.toJWTClaimsSet();
		
		if (jwtClaimsSet.getClaim("max_age") != null) {
			// Convert max_age to number in JSON object
			try {
				String maxAgeString = jwtClaimsSet.getStringClaim("max_age");
				JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(jwtClaimsSet);
				builder.claim("max_age", Integer.parseInt(maxAgeString));
				return builder.build();
			} catch (java.text.ParseException e) {
				throw new SerializeException(e.getMessage());
			}
		}
		
		return jwtClaimsSet;
	}
	
	
	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * URI query parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = token id_token
	 * client_id     = s6BhdRkqt3
	 * redirect_uri  = https://client.example.com/cb
	 * scope         = openid profile
	 * state         = af0ifjsldkj
	 * nonce         = -0S6_WzA2Mj
	 * </pre>
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final Map<String,List<String>> params)
		throws ParseException {

		return parse(null, params);
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * URI and query parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * response_type = token id_token
	 * client_id     = s6BhdRkqt3
	 * redirect_uri  = https://client.example.com/cb
	 * scope         = openid profile
	 * state         = af0ifjsldkj
	 * nonce         = -0S6_WzA2Mj
	 * </pre>
	 *
	 * @param uri    The URI of the OAuth 2.0 authorisation endpoint. May
	 *               be {@code null} if the {@link #toHTTPRequest} method
	 *               will not be used.
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final URI uri, final Map<String,List<String>> params)
		throws ParseException {

		// Parse and validate the core OAuth 2.0 autz request params in 
		// the context of OIDC
		AuthorizationRequest ar = AuthorizationRequest.parse(uri, params);
		
		Nonce nonce = Nonce.parse(MultivaluedMapUtils.getFirstValue(params, "nonce"));
		
		if (! ar.specifiesRequestObject()) {
			
			// Required params if no JAR is present
			
			if (ar.getRedirectionURI() == null) {
				String msg = "Missing redirect_uri parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					ar.getClientID(), null, ar.impliedResponseMode(), ar.getState());
			}
			
			if (ar.getScope() == null) {
				String msg = "Missing scope parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
			}
			
			// Check nonce requirement
			if (nonce == null && Nonce.isRequired(ar.getResponseType())) {
				String msg = "Missing nonce parameter: Required for response_type=" + ar.getResponseType();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
			}
		}
		
		// Check if present (not in JAR)
		if (ar.getResponseType() != null) {
			try {
				OIDCResponseTypeValidator.validate(ar.getResponseType());
			} catch (IllegalArgumentException e) {
				String msg = "Unsupported response_type parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.appendDescription(": " + msg),
					ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
			}
		}
		
		// Check if present (not in JAR)
		if (ar.getScope() != null && ! ar.getScope().contains(OIDCScopeValue.OPENID)) {
			String msg = "The scope must include an openid value";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
		}
		
		Display display = null;

		if (params.containsKey("display")) {
			try {
				display = Display.parse(MultivaluedMapUtils.getFirstValue(params, "display"));

			} catch (ParseException e) {
				String msg = "Invalid display parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
			}
		}


		String v = MultivaluedMapUtils.getFirstValue(params, "max_age");

		int maxAge = -1;

		if (StringUtils.isNotBlank(v)) {

			try {
				maxAge = Integer.parseInt(v);

			} catch (NumberFormatException e) {
				String msg = "Invalid max_age parameter";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
			}
		}


		List<LangTag> uiLocales;
		try {
			uiLocales = LangTagUtils.parseLangTagList(MultivaluedMapUtils.getFirstValue(params, "ui_locales"));
		} catch (LangTagException e) {
			String msg = "Invalid ui_locales parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
		}


		List<LangTag> claimsLocales;
		try {
			claimsLocales = LangTagUtils.parseLangTagList(MultivaluedMapUtils.getFirstValue(params, "claims_locales"));
			
		} catch (LangTagException e) {
			String msg = "Invalid claims_locales parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
		}


		v = MultivaluedMapUtils.getFirstValue(params, "id_token_hint");
		
		JWT idTokenHint = null;
		
		if (StringUtils.isNotBlank(v)) {
		
			try {
				idTokenHint = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
				String msg = "Invalid id_token_hint parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
			}
		}

		String loginHint = MultivaluedMapUtils.getFirstValue(params, "login_hint");


		v = MultivaluedMapUtils.getFirstValue(params, "acr_values");

		List<ACR> acrValues = null;

		if (StringUtils.isNotBlank(v)) {

			acrValues = new LinkedList<>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				acrValues.add(new ACR(st.nextToken()));
			}
		}


		v = MultivaluedMapUtils.getFirstValue(params, "claims");

		OIDCClaimsRequest claims = null;

		if (StringUtils.isNotBlank(v)) {
			try {
				claims = OIDCClaimsRequest.parse(v);
			} catch (ParseException e) {
				String msg = "Invalid claims parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState(), e);
			}
		}
		
		String purpose = MultivaluedMapUtils.getFirstValue(params, "purpose");
		
		if (purpose != null && (purpose.length() < PURPOSE_MIN_LENGTH || purpose.length() > PURPOSE_MAX_LENGTH)) {
			String msg = "Invalid purpose parameter: Must not be shorter than " + PURPOSE_MIN_LENGTH + " and longer than " + PURPOSE_MAX_LENGTH + " characters";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				ar.getClientID(), ar.getRedirectionURI(), ar.impliedResponseMode(), ar.getState());
		}
		

		// Parse additional custom parameters
		Map<String,List<String>> customParams = null;

		for (Map.Entry<String,List<String>> p: params.entrySet()) {

			if (! REGISTERED_PARAMETER_NAMES.contains(p.getKey())) {
				// We have a custom parameter
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				customParams.put(p.getKey(), p.getValue());
			}
		}


		return new AuthenticationRequest(
			uri, ar.getResponseType(), ar.getResponseMode(), ar.getScope(), ar.getClientID(), ar.getRedirectionURI(), ar.getState(), nonce,
			display, ar.getPrompt(), ar.getDPoPJWKThumbprintConfirmation(), ar.getTrustChain(), maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, purpose,
			ar.getRequestObject(), ar.getRequestURI(),
			ar.getCodeChallenge(), ar.getCodeChallengeMethod(),
			ar.getAuthorizationDetails(),
			ar.getResources(),
			ar.includeGrantedScopes(),
			customParams);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * URI query string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=token%20id_token
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &amp;scope=openid%20profile
	 * &amp;state=af0ifjsldkj
	 * &amp;nonce=n-0S6_WzA2Mj
	 * </pre>
	 *
	 * @param query The URI query string. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an 
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final String query)
		throws ParseException {
	
		return parse(null, URLUtils.parseParameters(query));
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * URI query string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * response_type=token%20id_token
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &amp;scope=openid%20profile
	 * &amp;state=af0ifjsldkj
	 * &amp;nonce=n-0S6_WzA2Mj
	 * </pre>
	 *
	 * @param uri   The URI of the OAuth 2.0 authorisation endpoint. May be
	 *              {@code null} if the {@link #toHTTPRequest} method will
	 *              not be used.
	 * @param query The URI query string. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final URI uri, final String query)
		throws ParseException {

		return parse(uri, URLUtils.parseParameters(query));
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/authorize?
	 * response_type=token%20id_token
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &amp;scope=openid%20profile
	 * &amp;state=af0ifjsldkj
	 * &amp;nonce=n-0S6_WzA2Mj
	 * </pre>
	 *
	 * @param uri The URI. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to an
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), URLUtils.parseParameters(uri.getRawQuery()));
	}
	
	
	/**
	 * Parses an authentication request from the specified HTTP GET or POST
	 * request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * https://server.example.com/op/authorize?
	 * response_type=code%20id_token
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
	 * &amp;scope=openid
	 * &amp;nonce=n-0S6_WzA2Mj
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        OpenID Connect authentication request.
	 */
	public static AuthenticationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		if (HTTPRequest.Method.GET.equals(httpRequest.getMethod())) {
			return parse(URIUtils.getBaseURI(httpRequest.getURI()), httpRequest.getQueryStringParameters());
		}

		if (HTTPRequest.Method.POST.equals(httpRequest.getMethod())) {
			return parse(URIUtils.getBaseURI(httpRequest.getURI()), httpRequest.getBodyAsFormParameters());
		}

		throw new ParseException("HTTP GET or POST expected");
	}
}

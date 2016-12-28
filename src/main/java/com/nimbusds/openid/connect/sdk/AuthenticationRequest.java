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


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;
import org.apache.commons.lang3.StringUtils;


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
 *     <li>OpenID Connect Core 1.0, section 3.1.2.1.
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636).
 * </ul>
 */
@Immutable
public class AuthenticationRequest extends AuthorizationRequest {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<>();

		p.addAll(AuthorizationRequest.getRegisteredParameterNames());

		p.add("nonce");
		p.add("display");
		p.add("prompt");
		p.add("max_age");
		p.add("ui_locales");
		p.add("claims_locales");
		p.add("id_token_hint");
		p.add("login_hint");
		p.add("acr_values");
		p.add("claims");
		p.add("request_uri");
		p.add("request");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * The nonce (required for implicit flow, optional for code flow).
	 */
	private final Nonce nonce;
	
	
	/**
	 * The requested display type (optional).
	 */
	private final Display display;
	
	
	/**
	 * The requested prompt (optional).
	 */
	private final Prompt prompt;


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
	private final ClaimsRequest claims;
	
	
	/**
	 * Request object (optional).
	 */
	private final JWT requestObject;
	
	
	/**
	 * Request object URI (optional).
	 */
	private final URI requestURI;


	/**
	 * Builder for constructing OpenID Connect authentication requests.
	 */
	public static class Builder {


		/**
		 * The endpoint URI (optional).
		 */
		private URI uri;


		/**
		 * The response type (required).
		 */
		private final ResponseType rt;


		/**
		 * The client identifier (required).
		 */
		private final ClientID clientID;


		/**
		 * The redirection URI where the response will be sent
		 * (required).
		 */
		private final URI redirectURI;


		/**
		 * The scope (required).
		 */
		private final Scope scope;


		/**
		 * The opaque value to maintain state between the request and
		 * the callback (recommended).
		 */
		private State state;


		/**
		 * The nonce (required for implicit flow, optional for code
		 * flow).
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
		private ClaimsRequest claims;


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
		 * The additional custom parameters.
		 */
		private Map<String,String> customParams = new HashMap<>();


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

			if (clientID == null)
				throw new IllegalArgumentException("The client ID must not be null");

			this.clientID = clientID;

			// Check presence at build time
			this.redirectURI = redirectURI;
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
		 * Sets the nonce. Corresponds to the conditionally optional
		 * {@code nonce} parameter.
		 *
		 * @param nonce The nonce, {@code null} if not specified.
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
		 */
		public Builder prompt(final Prompt prompt) {

			this.prompt = prompt;
			return this;
		}


		/**
		 * Sets the required maximum authentication age. Corresponds to
		 * the optional {@code max_age} parameter.
		 *
		 * @param maxAge The maximum authentication age, in seconds; 0
		 *               if not specified.
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
		 */
		public Builder acrValues(final List<ACR> acrValues) {

			this.acrValues = acrValues;
			return this;
		}


		/**
		 * Sets the individual claims to be returned. Corresponds to
		 * the optional {@code claims} parameter.
		 *
		 * @param claims The individual claims to be returned,
		 *               {@code null} if not specified.
		 */
		public Builder claims(final ClaimsRequest claims) {

			this.claims = claims;
			return this;
		}


		/**
		 * Sets the request object. Corresponds to the optional
		 * {@code request} parameter. Must not be specified together
		 * with a request object URI.
		 *
		 * @return The request object, {@code null} if not specified.
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
		 * Sets the specified additional custom parameter.
		 *
		 * @param name  The parameter name. Must not be {@code null}.
		 * @param value The parameter value, {@code null} if not
		 *              specified.
		 *
		 * @return This builder.
		 */
		public Builder customParameter(final String name, final String value) {

			customParams.put(name, value);
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
					uri, rt, rm, scope, clientID, redirectURI, state, nonce,
					display, prompt, maxAge, uiLocales, claimsLocales,
					idTokenHint, loginHint, acrValues, claims,
					requestObject, requestURI,
					codeChallenge, codeChallengeMethod,
					customParams);

			} catch (IllegalArgumentException e) {

				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}
	
	
	/**
	 * Creates a new minimal OpenID Connect authentication request.
	 *
	 * @param uri         The URI of the OAuth 2.0 authorisation endpoint.
	 *                    May be {@code null} if the {@link #toHTTPRequest}
	 *                    method will not be used.
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
	public AuthenticationRequest(final URI uri,
				     final ResponseType rt,
				     final Scope scope,
				     final ClientID clientID,
				     final URI redirectURI,
				     final State state,
				     final Nonce nonce) {

		// Not specified: display, prompt, maxAge, uiLocales, claimsLocales, 
		// idTokenHint, loginHint, acrValues, claims
		// codeChallenge, codeChallengeMethod
		this(uri, rt, null, scope, clientID, redirectURI, state, nonce,
		     null, null, -1, null, null,
		     null, null, null, null, null, null,
			null, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect authentication request.
	 *
	 * @param uri                 The URI of the OAuth 2.0 authorisation
	 *                            endpoint. May be {@code null} if the
	 *                            {@link #toHTTPRequest} method will not be
	 *                            used.
	 * @param rt                  The response type set. Corresponds to the
	 *                            {@code response_type} parameter. Must
	 *                            specify a valid OpenID Connect response
	 *                            type. Must not be {@code null}.
	 * @param rm                  The response mode. Corresponds to the
	 *                            optional {@code response_mode} parameter.
	 *                            Use of this parameter is not recommended
	 *                            unless a non-default response mode is
	 *                            requested (e.g. form_post).
	 * @param scope               The request scope. Corresponds to the
	 *                            {@code scope} parameter. Must contain an
	 *                            {@link OIDCScopeValue#OPENID openid value}.
	 *                            Must not be {@code null}.
	 * @param clientID            The client identifier. Corresponds to the
	 *                            {@code client_id} parameter. Must not be
	 *                            {@code null}.
	 * @param redirectURI         The redirection URI. Corresponds to the
	 *                            {@code redirect_uri} parameter. Must not
	 *                            be {@code null} unless set by means of
	 *                            the optional {@code request_object} /
	 *                            {@code request_uri} parameter.
	 * @param state               The state. Corresponds to the recommended
	 *                            {@code state} parameter. {@code null} if
	 *                            not specified.
	 * @param nonce               The nonce. Corresponds to the
	 *                            {@code nonce} parameter. May be
	 *                            {@code null} for code flow.
	 * @param display             The requested display type. Corresponds
	 *                            to the optional {@code display}
	 *                            parameter.
	 *                            {@code null} if not specified.
	 * @param prompt              The requested prompt. Corresponds to the
	 *                            optional {@code prompt} parameter.
	 *                            {@code null} if not specified.
	 * @param maxAge              The required maximum authentication age,
	 *                            in seconds. Corresponds to the optional
	 *                            {@code max_age} parameter. Zero if not
	 *                            specified.
	 * @param uiLocales           The preferred languages and scripts for
	 *                            the user interface. Corresponds to the
	 *                            optional {@code ui_locales} parameter.
	 *                            {@code null} if not specified.
	 * @param claimsLocales       The preferred languages and scripts for
	 *                            claims being returned. Corresponds to the
	 *                            optional {@code claims_locales}
	 *                            parameter. {@code null} if not specified.
	 * @param idTokenHint         The ID Token hint. Corresponds to the
	 *                            optional {@code id_token_hint} parameter.
	 *                            {@code null} if not specified.
	 * @param loginHint           The login hint. Corresponds to the
	 *                            optional {@code login_hint} parameter.
	 *                            {@code null} if not specified.
	 * @param acrValues           The requested Authentication Context
	 *                            Class Reference values. Corresponds to
	 *                            the optional {@code acr_values}
	 *                            parameter. {@code null} if not specified.
	 * @param claims              The individual claims to be returned.
	 *                            Corresponds to the optional
	 *                            {@code claims} parameter. {@code null} if
	 *                            not specified.
	 * @param requestObject       The request object. Corresponds to the
	 *                            optional {@code request} parameter. Must
	 *                            not be specified together with a request
	 *                            object URI. {@code null} if not
	 *                            specified.
	 * @param requestURI          The request object URI. Corresponds to
	 *                            the optional {@code request_uri}
	 *                            parameter. Must not be specified together
	 *                            with a request object. {@code null} if
	 *                            not specified.
	 * @param codeChallenge       The code challenge for PKCE, {@code null}
	 *                            if not specified.
	 * @param codeChallengeMethod The code challenge method for PKCE,
	 *                            {@code null} if not specified.
	 */
	public AuthenticationRequest(final URI uri,
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
				     final JWT requestObject,
				     final URI requestURI,
				     final CodeChallenge codeChallenge,
				     final CodeChallengeMethod codeChallengeMethod) {

		this(uri, rt, rm, scope, clientID, redirectURI, state,
			nonce, display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims,
			requestObject, requestURI, codeChallenge, codeChallengeMethod,
			Collections.<String, String>emptyMap());
	}


	/**
	 * Creates a new OpenID Connect authentication request with additional
	 * custom parameters.
	 *
	 * @param uri                 The URI of the OAuth 2.0 authorisation
	 *                            endpoint. May be {@code null} if the
	 *                            {@link #toHTTPRequest} method will not be
	 *                            used.
	 * @param rt                  The response type set. Corresponds to the
	 *                            {@code response_type} parameter. Must
	 *                            specify a valid OpenID Connect response
	 *                            type. Must not be {@code null}.
	 * @param rm                  The response mode. Corresponds to the
	 *                            optional {@code response_mode} parameter.
	 *                            Use of this parameter is not recommended
	 *                            unless a non-default response mode is
	 *                            requested (e.g. form_post).
	 * @param scope               The request scope. Corresponds to the
	 *                            {@code scope} parameter. Must contain an
	 *                            {@link OIDCScopeValue#OPENID openid value}.
	 *                            Must not be {@code null}.
	 * @param clientID            The client identifier. Corresponds to the
	 *                            {@code client_id} parameter. Must not be
	 *                            {@code null}.
	 * @param redirectURI         The redirection URI. Corresponds to the
	 *                            {@code redirect_uri} parameter. Must not
	 *                            be {@code null} unless set by means of
	 *                            the optional {@code request_object} /
	 *                            {@code request_uri} parameter.
	 * @param state               The state. Corresponds to the recommended
	 *                            {@code state} parameter. {@code null} if
	 *                            not specified.
	 * @param nonce               The nonce. Corresponds to the
	 *                            {@code nonce} parameter. May be
	 *                            {@code null} for code flow.
	 * @param display             The requested display type. Corresponds
	 *                            to the optional {@code display}
	 *                            parameter.
	 *                            {@code null} if not specified.
	 * @param prompt              The requested prompt. Corresponds to the
	 *                            optional {@code prompt} parameter.
	 *                            {@code null} if not specified.
	 * @param maxAge              The required maximum authentication age,
	 *                            in seconds. Corresponds to the optional
	 *                            {@code max_age} parameter. -1 if not
	 *                            specified, zero implies
	 *                            {@code prompt=login}.
	 * @param uiLocales           The preferred languages and scripts for
	 *                            the user interface. Corresponds to the
	 *                            optional {@code ui_locales} parameter.
	 *                            {@code null} if not specified.
	 * @param claimsLocales       The preferred languages and scripts for
	 *                            claims being returned. Corresponds to the
	 *                            optional {@code claims_locales}
	 *                            parameter. {@code null} if not specified.
	 * @param idTokenHint         The ID Token hint. Corresponds to the
	 *                            optional {@code id_token_hint} parameter.
	 *                            {@code null} if not specified.
	 * @param loginHint           The login hint. Corresponds to the
	 *                            optional {@code login_hint} parameter.
	 *                            {@code null} if not specified.
	 * @param acrValues           The requested Authentication Context
	 *                            Class Reference values. Corresponds to
	 *                            the optional {@code acr_values}
	 *                            parameter. {@code null} if not specified.
	 * @param claims              The individual claims to be returned.
	 *                            Corresponds to the optional
	 *                            {@code claims} parameter. {@code null} if
	 *                            not specified.
	 * @param requestObject       The request object. Corresponds to the
	 *                            optional {@code request} parameter. Must
	 *                            not be specified together with a request
	 *                            object URI. {@code null} if not
	 *                            specified.
	 * @param requestURI          The request object URI. Corresponds to
	 *                            the optional {@code request_uri}
	 *                            parameter. Must not be specified together
	 *                            with a request object. {@code null} if
	 *                            not specified.
	 * @param codeChallenge       The code challenge for PKCE, {@code null}
	 *                            if not specified.
	 * @param codeChallengeMethod The code challenge method for PKCE,
	 *                            {@code null} if not specified.
	 * @param customParams        Additional custom parameters, empty map
	 *                            or {@code null} if none.
	 */
	public AuthenticationRequest(final URI uri,
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
				     final JWT requestObject,
				     final URI requestURI,
				     final CodeChallenge codeChallenge,
				     final CodeChallengeMethod codeChallengeMethod,
				     final Map<String,String> customParams) {

		super(uri, rt, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, customParams);

		// Redirect URI required unless set in request_object / request_uri
		if (redirectURI == null && requestObject == null && requestURI == null)
			throw new IllegalArgumentException("The redirection URI must not be null");
		
		OIDCResponseTypeValidator.validate(rt);

		if (scope == null)
			throw new IllegalArgumentException("The scope must not be null");

		if (! scope.contains(OIDCScopeValue.OPENID))
			throw new IllegalArgumentException("The scope must include an \"openid\" token");
		
		
		// Nonce required for implicit protocol flow
		if (rt.impliesImplicitFlow() && nonce == null)
			throw new IllegalArgumentException("Nonce is required in implicit / hybrid protocol flow");
		
		this.nonce = nonce;
		
		// Optional parameters
		this.display = display;
		this.prompt = prompt;
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

		if (requestObject != null && requestURI != null)
			throw new IllegalArgumentException("Either a request object or a request URI must be specified, but not both");

		this.requestObject = requestObject;
		this.requestURI = requestURI;
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
	 * Gets the nonce. Corresponds to the conditionally optional 
	 * {@code nonce} parameter.
	 *
	 * @return The nonce, {@code null} if not specified.
	 */
	public Nonce getNonce() {
	
		return nonce;
	}
	
	
	/**
	 * Gets the requested display type. Corresponds to the optional
	 * {@code display} parameter.
	 *
	 * @return The requested display type, {@code null} if not specified.
	 */
	public Display getDisplay() {
	
		return display;
	}
	
	
	/**
	 * Gets the requested prompt. Corresponds to the optional 
	 * {@code prompt} parameter.
	 *
	 * @return The requested prompt, {@code null} if not specified.
	 */
	public Prompt getPrompt() {
	
		return prompt;
	}


	/**
	 * Gets the required maximum authentication age. Corresponds to the
	 * optional {@code max_age} parameter.
	 *
	 * @return The maximum authentication age, in seconds; -1 if not
	 *         specified, zero implies {@code prompt=login}.
	 */
	public int getMaxAge() {
	
		return maxAge;
	}


	/**
	 * Gets the end-user's preferred languages and scripts for the user
	 * interface, ordered by preference. Corresponds to the optional
	 * {@code ui_locales} parameter.
	 *
	 * @return The preferred UI locales, {@code null} if not specified.
	 */
	public List<LangTag> getUILocales() {

		return uiLocales;
	}


	/**
	 * Gets the end-user's preferred languages and scripts for the claims
	 * being returned, ordered by preference. Corresponds to the optional
	 * {@code claims_locales} parameter.
	 *
	 * @return The preferred claims locales, {@code null} if not specified.
	 */
	public List<LangTag> getClaimsLocales() {

		return claimsLocales;
	}


	/**
	 * Gets the ID Token hint. Corresponds to the conditionally optional 
	 * {@code id_token_hint} parameter.
	 *
	 * @return The ID Token hint, {@code null} if not specified.
	 */
	public JWT getIDTokenHint() {
	
		return idTokenHint;
	}


	/**
	 * Gets the login hint. Corresponds to the optional {@code login_hint} 
	 * parameter.
	 *
	 * @return The login hint, {@code null} if not specified.
	 */
	public String getLoginHint() {

		return loginHint;
	}


	/**
	 * Gets the requested Authentication Context Class Reference values.
	 * Corresponds to the optional {@code acr_values} parameter.
	 *
	 * @return The requested ACR values, {@code null} if not specified.
	 */
	public List<ACR> getACRValues() {

		return acrValues;
	}


	/**
	 * Gets the individual claims to be returned. Corresponds to the 
	 * optional {@code claims} parameter.
	 *
	 * @return The individual claims to be returned, {@code null} if not
	 *         specified.
	 */
	public ClaimsRequest getClaims() {

		return claims;
	}
	
	
	/**
	 * Gets the request object. Corresponds to the optional {@code request} 
	 * parameter.
	 *
	 * @return The request object, {@code null} if not specified.
	 */
	public JWT getRequestObject() {
	
		return requestObject;
	}
	
	
	/**
	 * Gets the request object URI. Corresponds to the optional
	 * {@code request_uri} parameter.
	 *
	 * @return The request object URI, {@code null} if not specified.
	 */
	public URI getRequestURI() {
	
		return requestURI;
	}
	
	
	/**
	 * Returns {@code true} if this authentication request specifies an
	 * OpenID Connect request object (directly through the {@code request} 
	 * parameter or by reference through the {@code request_uri} parameter).
	 *
	 * @return {@code true} if a request object is specified, else 
	 *         {@code false}.
	 */
	public boolean specifiesRequestObject() {
	
		return requestObject != null || requestURI != null;
	}


	@Override
	public Map<String,String> toParameters() {

		Map <String,String> params = super.toParameters();
		
		if (nonce != null)
			params.put("nonce", nonce.toString());
		
		if (display != null)
			params.put("display", display.toString());
		
		if (prompt != null)
			params.put("prompt", prompt.toString());

		if (maxAge >= 0)
			params.put("max_age", "" + maxAge);

		if (uiLocales != null) {

			StringBuilder sb = new StringBuilder();

			for (LangTag locale: uiLocales) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(locale.toString());
			}

			params.put("ui_locales", sb.toString());
		}

		if (claimsLocales != null) {

			StringBuilder sb = new StringBuilder();

			for (LangTag locale: claimsLocales) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(locale.toString());
			}

			params.put("claims_locales", sb.toString());
		}

		if (idTokenHint != null) {
		
			try {
				params.put("id_token_hint", idTokenHint.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize ID token hint: " + e.getMessage(), e);
			}
		}

		if (loginHint != null)
			params.put("login_hint", loginHint);

		if (acrValues != null) {

			StringBuilder sb = new StringBuilder();

			for (ACR acr: acrValues) {

				if (sb.length() > 0)
					sb.append(' ');

				sb.append(acr.toString());
			}

			params.put("acr_values", sb.toString());
		}
			

		if (claims != null)
			params.put("claims", claims.toJSONObject().toString());
		
		if (requestObject != null) {
		
			try {
				params.put("request", requestObject.serialize());
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize request object to JWT: " + e.getMessage(), e);
			}
		}
		
		if (requestURI != null)
			params.put("request_uri", requestURI.toString());

		return params;
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * parameters.
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
	public static AuthenticationRequest parse(final Map<String,String> params)
		throws ParseException {

		return parse(null, params);
	}


	/**
	 * Parses an OpenID Connect authentication request from the specified
	 * parameters.
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
	public static AuthenticationRequest parse(final URI uri, final Map<String,String> params)
		throws ParseException {

		// Parse and validate the core OAuth 2.0 autz request params in 
		// the context of OIDC
		AuthorizationRequest ar = AuthorizationRequest.parse(uri, params);

		ClientID clientID = ar.getClientID();
		State state = ar.getState();
		ResponseMode rm = ar.getResponseMode();

		// Required in OIDC, check later after optional request_object / request_uri is parsed
		URI redirectURI = ar.getRedirectionURI();

		ResponseType rt = ar.getResponseType();
		
		try {
			OIDCResponseTypeValidator.validate(rt);
			
		} catch (IllegalArgumentException e) {
			String msg = "Unsupported \"response_type\" parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.appendDescription(": " + msg),
					         clientID, redirectURI, ar.impliedResponseMode(), state);
		}
		
		// Required in OIDC, must include "openid" parameter
		Scope scope = ar.getScope();

		if (scope == null) {
			String msg = "Missing \"scope\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, ar.impliedResponseMode(), state);
		}

		if (! scope.contains(OIDCScopeValue.OPENID)) {
			String msg = "The scope must include an \"openid\" value";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, ar.impliedResponseMode(), state);
		}


		// Parse the remaining OIDC parameters
		Nonce nonce = Nonce.parse(params.get("nonce"));
		
		// Nonce required in implicit flow
		if (rt.impliesImplicitFlow() && nonce == null) {
			String msg = "Missing \"nonce\" parameter: Required in implicit flow";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, ar.impliedResponseMode(), state);
		}
		
		Display display = null;

		if (params.containsKey("display")) {
			try {
				display = Display.parse(params.get("display"));

			} catch (ParseException e) {
				String msg = "Invalid \"display\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					clientID, redirectURI, ar.impliedResponseMode(), state, e);
			}
		}
		
		
		Prompt prompt;
		
		try {
			prompt = Prompt.parse(params.get("prompt"));
				
		} catch (ParseException e) {
			String msg = "Invalid \"prompt\" parameter: " + e.getMessage();
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
		}


		String v = params.get("max_age");

		int maxAge = -1;

		if (StringUtils.isNotBlank(v)) {

			try {
				maxAge = Integer.parseInt(v);

			} catch (NumberFormatException e) {
				String msg = "Invalid \"max_age\" parameter: " + v;
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
			}
		}


		v = params.get("ui_locales");

		List<LangTag> uiLocales = null;

		if (StringUtils.isNotBlank(v)) {

			uiLocales = new LinkedList<>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				try {
					uiLocales.add(LangTag.parse(st.nextToken()));

				} catch (LangTagException e) {
					String msg = "Invalid \"ui_locales\" parameter: " + e.getMessage();
					throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
						                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
				}
			}
		}


		v = params.get("claims_locales");

		List<LangTag> claimsLocales = null;

		if (StringUtils.isNotBlank(v)) {

			claimsLocales = new LinkedList<>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				try {
					claimsLocales.add(LangTag.parse(st.nextToken()));

				} catch (LangTagException e) {
					String msg = "Invalid \"claims_locales\" parameter: " + e.getMessage();
					throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
						                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
				}
			}
		}


		v = params.get("id_token_hint");
		
		JWT idTokenHint = null;
		
		if (StringUtils.isNotBlank(v)) {
		
			try {
				idTokenHint = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
				String msg = "Invalid \"id_token_hint\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
			}
		}

		String loginHint = params.get("login_hint");


		v = params.get("acr_values");

		List<ACR> acrValues = null;

		if (StringUtils.isNotBlank(v)) {

			acrValues = new LinkedList<>();

			StringTokenizer st = new StringTokenizer(v, " ");

			while (st.hasMoreTokens()) {

				acrValues.add(new ACR(st.nextToken()));
			}
		}


		v = params.get("claims");

		ClaimsRequest claims = null;

		if (StringUtils.isNotBlank(v)) {

			JSONObject jsonObject;

			try {
				jsonObject = JSONObjectUtils.parse(v);

			} catch (ParseException e) {
				String msg = "Invalid \"claims\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
			}

			// Parse exceptions silently ignored
			claims = ClaimsRequest.parse(jsonObject);
		}
		
		
		v = params.get("request_uri");
		
		URI requestURI = null;
		
		if (StringUtils.isNotBlank(v)) {

			try {
				requestURI = new URI(v);
		
			} catch (URISyntaxException e) {
				String msg = "Invalid \"request_uri\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
			}
		}

		v = params.get("request");

		JWT requestObject = null;

		if (StringUtils.isNotBlank(v)) {

			// request_object and request_uri must not be defined at the same time
			if (requestURI != null) {
				String msg = "Invalid request: Found mutually exclusive \"request\" and \"request_uri\" parameters";
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, ar.impliedResponseMode(), state, null);
			}

			try {
				requestObject = JWTParser.parse(v);
				
			} catch (java.text.ParseException e) {
				String msg = "Invalid \"request_object\" parameter: " + e.getMessage();
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
					                 clientID, redirectURI, ar.impliedResponseMode(), state, e);
			}
		}


		// Redirect URI required unless request_object / request_uri present
		if (redirectURI == null && requestObject == null && requestURI == null) {
			String msg = "Missing \"redirect_uri\" parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg),
				clientID, null, ar.impliedResponseMode(), state);
		}

		// Parse additional custom parameters
		Map<String,String> customParams = null;

		for (Map.Entry<String,String> p: params.entrySet()) {

			if (! REGISTERED_PARAMETER_NAMES.contains(p.getKey())) {
				// We have a custom parameter
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				customParams.put(p.getKey(), p.getValue());
			}
		}


		return new AuthenticationRequest(
			uri, rt, rm, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, requestObject, requestURI,
			ar.getCodeChallenge(), ar.getCodeChallengeMethod(),
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
	 * Parses an authentication request from the specified HTTP GET or HTTP
	 * POST request.
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
		
		String query = httpRequest.getQuery();
		
		if (query == null)
			throw new ParseException("Missing URI query string");

		URI endpointURI;

		try {
			endpointURI = httpRequest.getURL().toURI();

		} catch (URISyntaxException e) {

			throw new ParseException(e.getMessage(), e);
		}
		
		return parse(endpointURI, query);
	}
}

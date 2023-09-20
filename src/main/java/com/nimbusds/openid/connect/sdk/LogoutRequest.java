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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;


/**
 * Logout request initiated by an OpenID relying party (RP). Supports HTTP GET
 * and POST. HTTP POST is the recommended method to protect the optional ID
 * token hint parameter from potentially getting recorded in access logs.
 *
 * <p>Example HTTP POST request:
 *
 * <pre>
 * POST /op/logout HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * id_token_hint=eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient.example.org%2Fpost-logout
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Example URL for an HTTP GET request:
 *
 * <pre>
 * https://server.example.com/op/logout?
 * id_token_hint=eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient.example.org%2Fpost-logout
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect RP-Initiated Logout 1.0, section 2.
 * </ul>
 */
@Immutable
public class LogoutRequest extends AbstractRequest {


	/**
	 * The ID token hint (recommended).
	 */
	private final JWT idTokenHint;
	
	
	/**
	 * The logout hint (optional).
	 */
	private final String logoutHint;
	
	
	/**
	 * The client ID (optional).
	 */
	private final ClientID clientID;


	/**
	 * The post-logout redirection URI (optional).
	 */
	private final URI postLogoutRedirectURI;


	/**
	 * The state parameter (optional).
	 */
	private final State state;
	
	
	/**
	 * The UI locales (optional).
	 */
	private final List<LangTag> uiLocales;
	
	
	/**
	 * Creates a new OpenID Connect logout request.
	 *
	 * @param uri                   The URI of the end-session endpoint.
	 *                              May be {@code null} if the
	 *                              {@link #toHTTPRequest} method will not
	 *                              be used.
	 * @param idTokenHint           The ID token hint (recommended),
	 *                              {@code null} if not specified.
	 * @param logoutHint            The optional logout hint, {@code null}
	 *                              if not specified.
	 * @param clientID              The optional client ID, {@code null} if
	 *                              not specified.
	 * @param postLogoutRedirectURI The optional post-logout redirection
	 *                              URI, {@code null} if not specified.
	 * @param state                 The optional state parameter for the
	 *                              post-logout redirection URI,
	 *                              {@code null} if not specified.
	 * @param uiLocales             The optional end-user's preferred
	 *                              languages and scripts for the user
	 *                              interface, ordered by preference.
	 */
	public LogoutRequest(final URI uri,
			     final JWT idTokenHint,
			     final String logoutHint,
			     final ClientID clientID,
			     final URI postLogoutRedirectURI,
			     final State state,
			     final List<LangTag> uiLocales) {
		super(uri);
		this.idTokenHint = idTokenHint;
		this.logoutHint = logoutHint;
		this.clientID = clientID;
		this.postLogoutRedirectURI = postLogoutRedirectURI;
		if (postLogoutRedirectURI == null && state != null) {
			throw new IllegalArgumentException("The state parameter requires a post-logout redirection URI");
		}
		this.state = state;
		this.uiLocales = uiLocales;
	}
	
	
	/**
	 * Creates a new OpenID Connect logout request.
	 *
	 * @param uri                   The URI of the end-session endpoint.
	 *                              May be {@code null} if the
	 *                              {@link #toHTTPRequest} method will not
	 *                              be used.
	 * @param idTokenHint           The ID token hint (recommended),
	 *                              {@code null} if not specified.
	 * @param postLogoutRedirectURI The optional post-logout redirection
	 *                              URI, {@code null} if not specified.
	 * @param state                 The optional state parameter for the
	 *                              post-logout redirection URI,
	 *                              {@code null} if not specified.
	 */
	public LogoutRequest(final URI uri,
			     final JWT idTokenHint,
			     final URI postLogoutRedirectURI,
			     final State state) {
		this(uri, idTokenHint, null, null, postLogoutRedirectURI, state, null);
	}


	/**
	 * Creates a new OpenID Connect logout request without a post-logout
	 * redirection.
	 *
	 * @param uri         The URI of the end-session endpoint. May be
	 *                    {@code null} if the {@link #toHTTPRequest} method
	 *                    will not be used.
	 * @param idTokenHint The ID token hint (recommended), {@code null} if
	 *                    not specified.
	 */
	public LogoutRequest(final URI uri,
			     final JWT idTokenHint) {
		this(uri, idTokenHint, null, null);
	}
	
	
	/**
	 * Creates a new OpenID Connect logout request without a post-logout
	 * redirection.
	 *
	 * @param uri The URI of the end-session endpoint. May be {@code null}
	 *            if the {@link #toHTTPRequest} method will not be used.
	 */
	public LogoutRequest(final URI uri) {
		this(uri, null, null, null);
	}


	/**
	 * Returns the ID token hint. Corresponds to the optional
	 * {@code id_token_hint} parameter.
	 *
	 * @return The ID token hint, {@code null} if not specified.
	 */
	public JWT getIDTokenHint() {
		return idTokenHint;
	}
	
	
	/**
	 * Returns the logout hint. Corresponds to the optional
	 * {@code logout_hint}  parameter.
	 *
	 * @return The logout hint, {@code null} if not specified.
	 */
	public String getLogoutHint() {
		return logoutHint;
	}
	
	
	/**
	 * Returns the client ID. Corresponds to the optional {@code client_id}
	 * parameter.
	 *
	 * @return The client ID, {@code null} if not specified.
	 */
	public ClientID getClientID() {
		return clientID;
	}
	
	
	/**
	 * Return the post-logout redirection URI.
	 *
	 * @return The post-logout redirection URI, {@code null} if not
	 *         specified.
	 */
	public URI getPostLogoutRedirectionURI() {
		return postLogoutRedirectURI;
	}


	/**
	 * Returns the state parameter for a post-logout redirection URI.
	 * Corresponds to the optional {@code state} parameter.
	 *
	 * @return The state parameter, {@code null} if not specified.
	 */
	public State getState() {
		return state;
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
	 * Returns the parameters for this logout request.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * post_logout_redirect_uri = https://client.example.com/post-logout
	 * state = af0ifjsldkj
	 * </pre>
	 *
	 * @return The parameters.
	 */
	public Map<String,List<String>> toParameters() {

		Map <String,List<String>> params = new LinkedHashMap<>();
		
		if (getIDTokenHint() != null) {
			try {
				params.put("id_token_hint", Collections.singletonList(getIDTokenHint().serialize()));
			} catch (IllegalStateException e) {
				throw new SerializeException("Couldn't serialize ID token: " + e.getMessage(), e);
			}
		}
		
		if (getLogoutHint() != null) {
			params.put("logout_hint", Collections.singletonList(getLogoutHint()));
		}
		
		if (getClientID() != null) {
			params.put("client_id", Collections.singletonList(getClientID().getValue()));
		}

		if (getPostLogoutRedirectionURI() != null) {
			params.put("post_logout_redirect_uri", Collections.singletonList(getPostLogoutRedirectionURI().toString()));
		}

		if (getState() != null) {
			params.put("state", Collections.singletonList(getState().getValue()));
		}
		
		if (getUILocales() != null) {
			params.put("ui_locales", Collections.singletonList(LangTagUtils.concat(getUILocales())));
		}

		return params;
	}


	/**
	 * Returns the URI query string for this logout request.
	 *
	 * <p>Note that the '?' character preceding the query string in a URI
	 * is not included in the returned string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @return The URI query string.
	 */
	public String toQueryString() {
		return URLUtils.serializeParameters(toParameters());
	}


	/**
	 * Returns the complete URI representation for this logout request,
	 * consisting of the {@link #getEndpointURI end-session endpoint URI}
	 * with the {@link #toQueryString query string} appended.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/logout?
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @return The URI representation.
	 */
	public URI toURI() {

		if (getEndpointURI() == null)
			throw new SerializeException("The end-session endpoint URI is not specified");

		final Map<String, List<String>> mergedQueryParams = new HashMap<>(URLUtils.parseParameters(getEndpointURI().getQuery()));
		mergedQueryParams.putAll(toParameters());
		String query = URLUtils.serializeParameters(mergedQueryParams);
		if (StringUtils.isNotBlank(query)) {
			query = '?' + query;
		}
		try {
			return new URI(URIUtils.getBaseURI(getEndpointURI()) + query);
		} catch (URISyntaxException e) {
			throw new SerializeException(e.getMessage(), e);
		}
	}


	@Override
	public HTTPRequest toHTTPRequest() {

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
		
		Map<String, List<String>> mergedQueryParams = new LinkedHashMap<>(URLUtils.parseParameters(getEndpointURI().getQuery()));
		mergedQueryParams.putAll(toParameters());

		URL baseURL;
		try {
			baseURL = URLUtils.getBaseURL(getEndpointURI().toURL());
		} catch (MalformedURLException e) {
			throw new SerializeException(e.getMessage(), e);
		}

		HTTPRequest httpRequest;
		httpRequest = new HTTPRequest(HTTPRequest.Method.POST, baseURL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody(URLUtils.serializeParameters(mergedQueryParams));
		return httpRequest;
	}


	/**
	 * Parses a logout request from the specified parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * post_logout_redirect_uri = https://client.example.com/post-logout
	 * state = af0ifjsldkj
	 * </pre>
	 *
	 * @param params The parameters, empty map if none. Must not be
	 *               {@code null}.
	 *
	 * @return The logout request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to a
	 *                        logout request.
	 */
	public static LogoutRequest parse(final Map<String,List<String>> params)
		throws ParseException {

		return parse(null, params);
	}


	/**
	 * Parses a logout request from the specified URI and query parameters.
	 *
	 * <p>Example parameters:
	 *
	 * <pre>
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * post_logout_redirect_uri = https://client.example.com/post-logout
	 * state = af0ifjsldkj
	 * </pre>
	 *
	 * @param uri    The URI of the end-session endpoint. May be
	 *               {@code null} if the {@link #toHTTPRequest()} method
	 *               will not be used.
	 * @param params The parameters, empty map if none. Must not be
	 *               {@code null}.
	 *
	 * @return The logout request.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to a
	 *                        logout request.
	 */
	public static LogoutRequest parse(final URI uri, final Map<String,List<String>> params)
		throws ParseException {

		String v = MultivaluedMapUtils.getFirstValue(params, "id_token_hint");

		JWT idTokenHint = null;
		
		if (StringUtils.isNotBlank(v)) {
			
			try {
				idTokenHint = JWTParser.parse(v);
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid id_token_hint: " + e.getMessage(), e);
			}
		}
		
		String logoutHint = MultivaluedMapUtils.getFirstValue(params, "logout_hint");
		
		ClientID clientID = null;
		
		v = MultivaluedMapUtils.getFirstValue(params, "client_id");
		
		if (StringUtils.isNotBlank(v)) {
			clientID = new ClientID(v);
		}

		v = MultivaluedMapUtils.getFirstValue(params, "post_logout_redirect_uri");

		URI postLogoutRedirectURI = null;

		if (StringUtils.isNotBlank(v)) {
			try {
				postLogoutRedirectURI = new URI(v);
			} catch (URISyntaxException e) {
				throw new ParseException("Invalid post_logout_redirect_uri parameter: " + e.getMessage(),  e);
			}
		}

		State state = null;

		v = MultivaluedMapUtils.getFirstValue(params, "state");

		if (postLogoutRedirectURI != null && StringUtils.isNotBlank(v)) {
			state = new State(v);
		}
		
		List<LangTag> uiLocales;
		try {
			uiLocales = LangTagUtils.parseLangTagList(MultivaluedMapUtils.getFirstValue(params, "ui_locales"));
		} catch (LangTagException e) {
			throw new ParseException("Invalid ui_locales parameter: " + e.getMessage(), e);
		}

		return new LogoutRequest(uri, idTokenHint, logoutHint, clientID, postLogoutRedirectURI, state, uiLocales);
	}


	/**
	 * Parses a logout request from the specified URI query string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param query The URI query string, {@code null} if none.
	 *
	 * @return The logout request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to a
	 *                        logout request.
	 */
	public static LogoutRequest parse(final String query)
		throws ParseException {

		return parse(null, URLUtils.parseParameters(query));
	}


	/**
	 * Parses a logout request from the specified URI query string.
	 *
	 * <p>Example URI query string:
	 *
	 * <pre>
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param uri   The URI of the end-session endpoint. May be
	 *              {@code null} if the {@link #toHTTPRequest()} method
	 *              will not be used.
	 * @param query The URI query string, {@code null} if none.
	 *
	 * @return The logout request.
	 *
	 * @throws ParseException If the query string couldn't be parsed to a
	 *                        logout request.
	 */
	public static LogoutRequest parse(final URI uri, final String query)
		throws ParseException {

		return parse(uri, URLUtils.parseParameters(query));
	}


	/**
	 * Parses a logout request from the specified URI.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://server.example.com/logout?
	 * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param uri The URI. Must not be {@code null}.
	 *
	 * @return The logout request.
	 *
	 * @throws ParseException If the URI couldn't be parsed to a logout
	 *                        request.
	 */
	public static LogoutRequest parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), URLUtils.parseParameters(uri.getRawQuery()));
	}


	/**
	 * Parses a logout request from the specified HTTP GET or POST request.
	 *
	 * <p>Example HTTP POST request:
	 *
	 * <pre>
	 * POST /op/logout HTTP/1.1
	 * Host: server.example.com
	 * Content-Type: application/x-www-form-urlencoded
	 *
	 * id_token_hint=eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
	 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient.example.org%2Fpost-logout
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The logout request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        logout request.
	 */
	public static LogoutRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		if (HTTPRequest.Method.POST.equals(httpRequest.getMethod())) {
			httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);
			return LogoutRequest.parse(httpRequest.getURI(), httpRequest.getBodyAsFormParameters());
		}

		if (HTTPRequest.Method.GET.equals(httpRequest.getMethod())) {
			return LogoutRequest.parse(httpRequest.getURI());
		}

		throw new ParseException("The HTTP request method must be POST or GET");
	}
}

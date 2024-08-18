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

package com.nimbusds.oauth2.sdk.device;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.*;


/**
 * Device authorisation request. Used to start the authorisation flow for
 * browserless and input constraint devices. Supports custom request
 * parameters.
 *
 * <p>Extending classes may define additional request parameters as well as
 * enforce tighter requirements on the base parameters.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /device_authorization HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * client_id=459691054427
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 * </ul>
 */
@Immutable
public class DeviceAuthorizationRequest extends AbstractOptionallyIdentifiedRequest {

	
	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;

	static {
		Set<String> p = new HashSet<>();

		p.add("client_id");
		p.add("scope");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The scope (optional).
	 */
	private final Scope scope;


	/**
	 * Custom parameters.
	 */
	private final Map<String, List<String>> customParams;


	/**
	 * Builder for constructing authorisation requests.
	 */
	public static class Builder {

		/**
		 * The endpoint URI (optional).
		 */
		private URI endpoint;


		/**
		 * The client authentication (optional).
		 */
		private final ClientAuthentication clientAuth;


		/**
		 * The client identifier (required if not authenticated).
		 */
		private final ClientID clientID;


		/**
		 * The scope (optional).
		 */
		private Scope scope;


		/**
		 * Custom parameters.
		 */
		private final Map<String, List<String>> customParams = new HashMap<>();


		/**
		 * Creates a new device authorization request builder.
		 *
		 * @param clientID The client identifier. Corresponds to the
		 *                 {@code client_id} parameter. Must not be
		 *                 {@code null}.
		 */
		public Builder(final ClientID clientID) {
			this.clientID = Objects.requireNonNull(clientID);
			this.clientAuth = null;
		}


		/**
		 * Creates a new device authorization request builder for an
		 * authenticated request.
		 *
		 * @param clientAuth The client authentication. Must not be
		 *                   {@code null}.
		 */
		public Builder(final ClientAuthentication clientAuth) {
			this.clientID = null;
			this.clientAuth = Objects.requireNonNull(clientAuth);
		}


		/**
		 * Creates a new device authorization request builder from the
		 * specified request.
		 *
		 * @param request The device authorization request. Must not be
		 *                {@code null}.
		 */
		public Builder(final DeviceAuthorizationRequest request) {

			endpoint = request.getEndpointURI();
			clientAuth = request.getClientAuthentication();
			scope = request.scope;
			clientID = request.getClientID();
			customParams.putAll(request.getCustomParameters());
		}


		/**
		 * Sets the scope. Corresponds to the optional {@code scope}
		 * parameter.
		 *
		 * @param scope The scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder scope(final Scope scope) {

			this.scope = scope;
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
		public Builder customParameter(final String name, final String... values) {

			if (values == null || values.length == 0) {
				customParams.remove(name);
			} else {
				customParams.put(name, Arrays.asList(values));
			}

			return this;
		}


		/**
		 * Sets the URI of the device authorisation endpoint.
		 *
		 * @param endpoint The URI of the device authorisation
		 *                 endpoint. May be {@code null} if the request
		 *                 is not going to be serialised.
		 *
		 * @return This builder.
		 */
		public Builder endpointURI(final URI endpoint) {

			this.endpoint = endpoint;
			return this;
		}


		/**
		 * Builds a new device authorization request.
		 *
		 * @return The device authorization request.
		 */
		public DeviceAuthorizationRequest build() {

			try {
				if (clientAuth == null) {
					return new DeviceAuthorizationRequest(endpoint, clientID, scope, customParams);
				} else {
					return new DeviceAuthorizationRequest(endpoint, clientAuth, scope, customParams);
				}
			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}


	/**
	 * Creates a new minimal device authorization request.
	 *
	 * @param endpoint The URI of the device authorization endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method
	 *                 is not going to be used.
	 * @param clientID The client identifier. Corresponds to the
	 *                 {@code client_id} parameter. Must not be
	 *                 {@code null}.
	 */
	public DeviceAuthorizationRequest(final URI endpoint, final ClientID clientID) {

		this(endpoint, clientID, null, null);
	}


	/**
	 * Creates a new device authorization request.
	 *
	 * @param endpoint The URI of the device authorization endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method
	 *                 is not going to be used.
	 * @param clientID The client identifier. Corresponds to the
	 *                 {@code client_id} parameter. Must not be
	 *                 {@code null}.
	 * @param scope    The request scope. Corresponds to the optional
	 *                 {@code scope} parameter. {@code null} if not
	 *                 specified.
	 */
	public DeviceAuthorizationRequest(final URI endpoint, final ClientID clientID, final Scope scope) {

		this(endpoint, clientID, scope, null);
	}


	/**
	 * Creates a new device authorization request with extension and custom
	 * parameters.
	 *
	 * @param endpoint     The URI of the device authorization endpoint.
	 *                     May be {@code null} if the {@link #toHTTPRequest}
	 *                     method is not going to be used.
	 * @param clientID     The client identifier. Corresponds to the
	 *                     {@code client_id} parameter. Must not be
	 *                     {@code null}.
	 * @param scope        The request scope. Corresponds to the optional
	 *                     {@code scope} parameter. {@code null} if not
	 *                     specified.
	 * @param customParams Custom parameters, empty map or {@code null} if
	 *                     none.
	 */
	public DeviceAuthorizationRequest(final URI endpoint,
	                                  final ClientID clientID,
	                                  final Scope scope,
	                                  final Map<String, List<String>> customParams) {

		super(endpoint, Objects.requireNonNull(clientID));

		this.scope = scope;

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = Collections.unmodifiableMap(customParams);
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Creates a new authenticated device authorization request with
	 * extension and custom parameters.
	 *
	 * @param uri          The URI of the device authorization endpoint.
	 *                     May be {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param clientAuth   The client authentication. Must not be
	 *                     {@code null}.
	 * @param scope        The request scope. Corresponds to the optional
	 *                     {@code scope} parameter. {@code null} if not
	 *                     specified.
	 * @param customParams Custom parameters, empty map or {@code null} if
	 *                     none.
	 */
	public DeviceAuthorizationRequest(final URI uri,
	                                  final ClientAuthentication clientAuth,
	                                  final Scope scope,
	                                  final Map<String, List<String>> customParams) {

		super(uri, Objects.requireNonNull(clientAuth));

		this.scope = scope;

		if (MapUtils.isNotEmpty(customParams)) {
			this.customParams = Collections.unmodifiableMap(customParams);
		} else {
			this.customParams = Collections.emptyMap();
		}
	}


	/**
	 * Returns the registered (standard) OAuth 2.0 device authorization
	 * request parameter names.
	 *
	 * @return The registered OAuth 2.0 device authorization request
	 *         parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the scope. Corresponds to the optional {@code scope} parameter.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		return scope;
	}


	/**
	 * Returns the additional custom parameters.
	 *
	 * @return The additional custom parameters as an unmodifiable map,
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
		httpRequest.setAccept(ContentType.APPLICATION_JSON.getType()); // iss #451

		if (getClientAuthentication() != null) {
			getClientAuthentication().applyTo(httpRequest);
		}

		Map<String, List<String>> params;
		try {
			params = new LinkedHashMap<>(httpRequest.getBodyAsFormParameters());
		} catch (ParseException e) {
			throw new SerializeException(e.getMessage(), e);
		}

		if (scope != null && !scope.isEmpty()) {
			params.put("scope", Collections.singletonList(scope.toString()));
		}

		if (getClientID() != null) {
			params.put("client_id", Collections.singletonList(getClientID().getValue()));
		}

		if (!getCustomParameters().isEmpty()) {
			params.putAll(getCustomParameters());
		}

		httpRequest.setBody(URLUtils.serializeParameters(params));
		return httpRequest;
	}


	/**
	 * Parses a device authorization request from the specified HTTP
	 * request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * POST /device_authorization HTTP/1.1
	 * Host: server.example.com
	 * Content-Type: application/x-www-form-urlencoded
	 *
	 * client_id=459691054427
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The device authorization request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        device authorization request.
	 */
	public static DeviceAuthorizationRequest parse(final HTTPRequest httpRequest) throws ParseException {

		// Only HTTP POST accepted
		URI uri = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);

		// Parse client authentication, if any
		ClientAuthentication clientAuth;
		try {
			clientAuth = ClientAuthentication.parse(httpRequest);
		} catch (ParseException e) {
			throw new ParseException(e.getMessage(),
			                OAuth2Error.INVALID_REQUEST.appendDescription(": " + e.getMessage()));
		}

		Map<String, List<String>> params = httpRequest.getBodyAsFormParameters();

		ClientID clientID;
		String v;

		if (clientAuth == null) {
			// Parse mandatory client ID for unauthenticated requests
			v = MultivaluedMapUtils.getFirstValue(params, "client_id");

			if (StringUtils.isBlank(v)) {
				String msg = "Missing client_id parameter";
				throw new ParseException(msg,
				                OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			}

			clientID = new ClientID(v);
		} else {
			clientID = null;
		}

		// Parse optional scope
		v = MultivaluedMapUtils.getFirstValue(params, "scope");

		Scope scope = null;

		if (StringUtils.isNotBlank(v))
			scope = Scope.parse(v);

		// Parse custom parameters
		Map<String, List<String>> customParams = null;

		for (Map.Entry<String, List<String>> p : params.entrySet()) {

			if (!REGISTERED_PARAMETER_NAMES.contains(p.getKey())) {
				// We have a custom parameter
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				customParams.put(p.getKey(), p.getValue());
			}
		}

		if (clientAuth == null) {
			return new DeviceAuthorizationRequest(uri, clientID, scope, customParams);
		} else {
			return new DeviceAuthorizationRequest(uri, clientAuth, scope, customParams);
		}
	}
}

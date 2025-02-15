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

package com.nimbusds.oauth2.sdk.http;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.ThreadSafe;
import net.minidev.json.JSONObject;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;


/**
 * HTTP request with support for the parameters required to construct an 
 * {@link com.nimbusds.oauth2.sdk.Request OAuth 2.0 request message}.
 *
 * <p>Supported HTTP methods:
 *
 * <ul>
 *     <li>{@link Method#GET HTTP GET}
 *     <li>{@link Method#POST HTTP POST}
 *     <li>{@link Method#POST HTTP PUT}
 *     <li>{@link Method#POST HTTP DELETE}
 * </ul>
 *
 * <p>Supported request headers:
 *
 * <ul>
 *     <li>Content-Type
 *     <li>Authorization
 *     <li>Accept
 *     <li>Etc.
 * </ul>
 *
 * <p>Supported timeouts:
 *
 * <ul>
 *     <li>On HTTP connect
 *     <li>On HTTP response read
 * </ul>
 *
 * <p>HTTP 3xx redirection: follow (default) / don't follow
 */
@ThreadSafe
public class HTTPRequest extends HTTPMessage implements ReadOnlyHTTPRequest {


	/**
	 * Enumeration of the HTTP methods used in OAuth 2.0 requests.
	 */
	public enum Method {
	
		/**
		 * HTTP GET.
		 */
		GET,
		
		
		/**
		 * HTTP POST.
		 */
		POST,
		
		
		/**
		 * HTTP PUT.
		 */
		PUT,
		
		
		/**
		 * HTTP DELETE.
		 */
		DELETE
	}
	
	
	/**
	 * The request method.
	 */
	private final Method method;


	/**
	 * The request URL (mutable).
	 */
	private URL url;


	/**
	 * The HTTP connect timeout, in milliseconds. Zero implies none.
	 */
	private int connectTimeout = 0;


	/**
	 * The HTTP response read timeout, in milliseconds. Zero implies none.

	 */
	private int readTimeout = 0;

	
	/**
	 * Do not use a connection specific proxy by default.
	 */
	private Proxy proxy = null;

	/**
	 * Controls HTTP 3xx redirections.
	 */
	private boolean followRedirects = true;
	
	
	/**
	 * The received validated client X.509 certificate for a received HTTPS
	 * request, {@code null} if not specified.
	 */
	private X509Certificate clientX509Certificate = null;
	
	
	/**
	 * The subject DN of a received client X.509 certificate for a received
	 * HTTPS request, {@code null} if not specified.
	 */
	private String clientX509CertificateSubjectDN = null;
	
	
	/**
	 * The root issuer DN of a received client X.509 certificate for a
	 * received HTTPS request, {@code null} if not specified.
	 */
	private String clientX509CertificateRootDN = null;
	
	
	/**
	 * The hostname verifier to use for outgoing HTTPS requests,
	 * {@code null} implies the default one.
	 */
	private HostnameVerifier hostnameVerifier = null;
	
	
	/**
	 * The SSL socket factory to use for outgoing HTTPS requests,
	 * {@code null} implies the default one.
	 */
	private SSLSocketFactory sslSocketFactory = null;


	/**
	 * The default hostname verifier for all outgoing HTTPS requests.
	 */
	private static HostnameVerifier defaultHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();


	/**
	 * The default socket factory for all outgoing HTTPS requests.
	 */
	private static SSLSocketFactory defaultSSLSocketFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();


	/**
	 * If {@code true} disables swallowing of {@link IOException}s when the
	 * HTTP connection streams are closed.
	 */
	private boolean debugCloseStreams = false;


	/**
	 * Creates a new minimally specified HTTP request.
	 *
	 * @param method The HTTP request method. Must not be {@code null}.
	 * @param url    The HTTP request URL. Must not be {@code null}.
	 */
	public HTTPRequest(final Method method, final URL url) {
	
		if (method == null)
			throw new IllegalArgumentException("The HTTP method must not be null");
		
		this.method = method;


		if (url == null)
			throw new IllegalArgumentException("The HTTP URL must not be null");

		this.url = url;
	}
	
	
	/**
	 * Creates a new minimally specified HTTP request.
	 *
	 * @param method The HTTP request method. Must not be {@code null}.
	 * @param uri    The HTTP request URI. Must be a URL and not
	 *               {@code null}.
	 */
	public HTTPRequest(final Method method, final URI uri) {
		this(method, toURLWithUncheckedException(uri));
	}
	
	
	private static URL toURLWithUncheckedException(final URI uri) {
		try {
			return uri.toURL();
		} catch (MalformedURLException | IllegalArgumentException e) {
			throw new SerializeException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Gets the request method.
	 *
	 * @return The request method.
	 */
	@Override
	public Method getMethod() {
	
		return method;
	}


	/**
	 * Gets the request URL.
	 *
	 * @return The request URL.
	 */
	@Override
	public URL getURL() {

		return url;
	}


	/**
	 * Gets the request URL as URI.
	 *
	 * @return The request URL as URI.
	 */
	@Override
	public URI getURI() {
		
		try {
			return url.toURI();
		} catch (URISyntaxException e) {
			// Should never happen
			throw new IllegalStateException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Ensures this HTTP request has the specified method.
	 *
	 * @param expectedMethod The expected method. Must not be {@code null}.
	 *
	 * @throws ParseException If the method doesn't match the expected.
	 */
	public void ensureMethod(final Method expectedMethod)
		throws ParseException {
		
		if (method != expectedMethod)
			throw new ParseException("The HTTP request method must be " + expectedMethod);
	}
	
	
	/**
	 * Gets the {@code Authorization} header value.
	 *
	 * @return The {@code Authorization} header value, {@code null} if not 
	 *         specified.
	 */
	public String getAuthorization() {
	
		return getHeaderValue("Authorization");
	}
	
	
	/**
	 * Sets the {@code Authorization} header value.
	 *
	 * @param authz The {@code Authorization} header value, {@code null} if 
	 *              not specified.
	 */
	public void setAuthorization(final String authz) {
	
		setHeader("Authorization", authz);
	}
	
	
	/**
	 * Gets the {@code DPoP} header value.
	 *
	 * @return The {@code DPoP} header value, {@code null} if not specified
	 *         or parsing failed.
	 */
	public SignedJWT getDPoP() {
	
		try {
			return getPoPWithException();
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Gets the {@code DPoP} header value.
	 *
	 * @return The {@code DPoP} header value, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If JWT parsing failed.
	 */
	public SignedJWT getPoPWithException()
		throws ParseException {
		
		String dPoP = getHeaderValue("DPoP");
		if (dPoP == null) {
			return null;
		}
		
		try {
			return SignedJWT.parse(dPoP);
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Sets the {@code DPoP} header value.
	 *
	 * @param dPoPJWT The {@code DPoP} header value, {@code null} if not
	 *                specified.
	 */
	public void setDPoP(final SignedJWT dPoPJWT) {
	
		if (dPoPJWT != null) {
			setHeader("DPoP", dPoPJWT.serialize());
		} else {
			setHeader("DPoP", (String[]) null);
		}
	}


	/**
	 * Gets the {@code Accept} header value.
	 *
	 * @return The {@code Accept} header value, {@code null} if not
	 *         specified.
	 */
	public String getAccept() {

		return getHeaderValue("Accept");
	}


	/**
	 * Sets the {@code Accept} header value.
	 *
	 * @param accept The {@code Accept} header value, {@code null} if not
	 *               specified.
	 */
	public void setAccept(final String accept) {

		setHeader("Accept", accept);
	}


	/**
	 * Enables debugging of the closing of the HTTP connection streams.
	 *
	 * @param debugCloseStreams If {@code true} disables swallowing of
	 *                          {@link IOException}s when the HTTP
	 *                          connection streams are closed.
	 */
	void setDebugCloseStreams(final boolean debugCloseStreams) {

		this.debugCloseStreams = debugCloseStreams;
	}


	/**
	 * Appends the specified query parameters to the current HTTP request
	 * {@link #getURL() URL} query.
	 *
	 * <p>If the current URL has a query string the new query is appended
	 * with `&amp;` in front.
	 *
	 * @param queryParams The query parameters to append, empty or
	 *                    {@code null} if nothing to append.
	 *
	 * @throws IllegalArgumentException If the URL composition failed.
	 */
	public void appendQueryParameters(final Map<String,List<String>> queryParams) {

		if (MapUtils.isEmpty(queryParams)) {
			// Nothing to append
			return;
		}

		appendQueryString(URLUtils.serializeParameters(queryParams));
	}
	
	
	/**
	 * Appends the specified raw (encoded) query string to the current HTTP
	 * request {@link #getURL() URL} query.
	 *
	 * <p>If the current URL has a query string the new query is appended
	 * with `&amp;` in front.
	 *
	 * <p>The '?' character preceding the query string must not be
	 * included.
	 *
	 * <p>Example query string to append:
	 *
	 * <pre>
	 * client_id=123&amp;logout_hint=eepaeph8siot&amp;state=shah2key
	 * </pre>
	 *
	 * @param queryString The query string to append, blank or {@code null}
	 *                    if nothing to append.
	 *
	 * @throws IllegalArgumentException If the URL composition failed.
	 */
	public void appendQueryString(final String queryString) {

		if (StringUtils.isBlank(queryString)) {
			// Nothing to append
			return;
		}

		if (StringUtils.isNotBlank(queryString) && queryString.startsWith("?")) {
			throw new IllegalArgumentException("The query string must not start with ?");
		}

		// Append query string to the URL
		StringBuilder sb = new StringBuilder();

		if (StringUtils.isNotBlank(url.getQuery())) {
			sb.append(url.getQuery());
			sb.append('&');
		}
		sb.append(queryString);

		url = URLUtils.setEncodedQuery(url, sb.toString());
	}


	/**
	 * Gets the raw (encoded) query string if the request is HTTP GET or
	 * the entity body if the request is HTTP POST.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests is not included in the returned string.
	 *
	 * <p>Example query string (line breaks for clarity):
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @deprecated Use {@link #getURL()}.
	 *
	 * @return For HTTP GET requests the URL query string, for HTTP POST
	 *         requests the body. {@code null} if not specified.
	 */
	@Deprecated
	public String getQuery() {

		// Heuristics for deprecated API
		return Method.POST.equals(getMethod()) ? getBody() : getURL().getQuery();
	}


	/**
	 * Sets the raw (encoded) query string if the request is HTTP GET or
	 * the entity body if the request is HTTP POST.
	 *
	 * <p>Note that the '?' character preceding the query string in GET
	 * requests must not be included.
	 *
	 * <p>Example query string (line breaks for clarity):
	 *
	 * <pre>
	 * response_type=code
	 * &amp;client_id=s6BhdRkqt3
	 * &amp;state=xyz
	 * &amp;redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
	 * </pre>
	 *
	 * @deprecated Use {@link #appendQueryString(String)}.
	 *
	 * @param query For HTTP GET requests the URL query string, for HTTP
	 *              POST requests the body. {@code null} if not specified.
	 */
	@Deprecated
	public void setQuery(final String query) {

		if (Method.POST.equals(getMethod())) {
			setBody(query);
		} else {
			appendQueryString(query);
		}
	}


	/**
	 * Ensures this HTTP response has a specified query string or entity
	 * body.
	 *
	 * @throws ParseException If the query string or entity body is missing
	 *                        or empty.
	 */
	private void ensureQuery()
		throws ParseException {
		
		if (getQuery() == null || getQuery().trim().isEmpty())
			throw new ParseException("Missing or empty HTTP query string / entity body");
	}
	
	
	/**
	 * Gets the query string as a parameter map. The parameters are decoded
	 * according to {@code application/x-www-form-urlencoded}.
	 *
	 * @return The query string parameters to, decoded. If none the map
	 *         will be empty.
	 */
	public Map<String,List<String>> getQueryStringParameters() {
	
		return URLUtils.parseParameters(url.getQuery());
	}


	/**
	 * Gets the request query as a parameter map. The parameters are
	 * decoded according to {@code application/x-www-form-urlencoded}.
	 *
	 * @deprecated Use {@link #getQueryStringParameters()}.
	 *
	 * @return The request query parameters, decoded. If none the map will
	 *         be empty.
	 */
	@Deprecated
	public Map<String,List<String>> getQueryParameters() {

		return URLUtils.parseParameters(getQuery());
	}


	/**
	 * Gets the request query or entity body as a JSON Object.
	 *
	 * @deprecated Use {@link #getBodyAsJSONObject()}.
	 *
	 * @return The request query or entity body as a JSON object.
	 *
	 * @throws ParseException If the Content-Type header isn't 
	 *                        {@code application/json}, the request query
	 *                        or entity body is {@code null}, empty or 
	 *                        couldn't be parsed to a valid JSON object.
	 */
	@Deprecated
	public JSONObject getQueryAsJSONObject()
		throws ParseException {

		ensureEntityContentType(ContentType.APPLICATION_JSON);

		ensureQuery();

		return JSONObjectUtils.parse(getQuery());
	}


	/**
	 * Gets the raw (encoded) fragment of the URL.
	 *
	 * @deprecated Use {@link #getURL()}.
	 *
	 * @return The fragment, {@code null} if not specified.
	 */
	@Deprecated
	public String getFragment() {

		return url.getRef();
	}


	/**
	 * Sets the raw (encoded) fragment of the URL.
	 *
	 * @param fragment The fragment, {@code null} if not specified.
	 */
	public void setFragment(final String fragment) {

		url = URLUtils.setEncodedFragment(url, fragment);
	}


	@Override
	public int getConnectTimeout() {

		return connectTimeout;
	}


	/**
	 * Sets the HTTP connect timeout.
	 *
	 * @param connectTimeout The HTTP connect timeout, in milliseconds.
	 *                       Zero implies no timeout. Must not be negative.
	 */
	public void setConnectTimeout(final int connectTimeout) {

		if (connectTimeout < 0) {
			throw new IllegalArgumentException("The HTTP connect timeout must be zero or positive");
		}

		this.connectTimeout = connectTimeout;
	}


	@Override
	public int getReadTimeout() {

		return readTimeout;
	}


	/**
	 * Sets the HTTP response read timeout.
	 *
	 * @param readTimeout The HTTP response read timeout, in milliseconds.
	 *                    Zero implies no timeout. Must not be negative.
	 */
	public void setReadTimeout(final int readTimeout) {

		if (readTimeout < 0) {
			throw new IllegalArgumentException("The HTTP response read timeout must be zero or positive");
		}

		this.readTimeout = readTimeout;
	}

	/**
	 * Returns the proxy to use for this HTTP request.
	 *
	 * @return The connection specific proxy for this request, {@code null}
	 *         for the default proxy strategy.
	 */
	public Proxy getProxy() {
		
		return this.proxy;
	}
	

	/**
	 * Tunnels this HTTP request via the specified {@link Proxy} by
	 * directly configuring the proxy on the {@link java.net.URLConnection}.
	 * The proxy is only used for this instance and bypasses any other
	 * proxy settings (such as set via System properties or
	 * {@link java.net.ProxySelector}). Supplying {@code null} (the
	 * default) reverts to the default proxy strategy of
	 * {@link java.net.URLConnection}. If the goal is to avoid using a
	 * proxy at all supply {@link Proxy#NO_PROXY}.
	 *
	 * @param proxy The connection specific proxy to use, {@code null} to
	 *              use the default proxy strategy.
	 *
	 * @see URL#openConnection(Proxy)
	 */
	public void setProxy(final Proxy proxy) {
		
		this.proxy = proxy;
	}
	

	/**
	 * Gets the boolean setting whether HTTP redirects (requests with
	 * response code 3xx) should be automatically followed.
	 *
	 * @return {@code true} if HTTP redirects are automatically followed,
	 *         else {@code false}.
	 */
	public boolean getFollowRedirects() {

		return followRedirects;
	}


	/**
	 * Sets whether HTTP redirects (requests with response code 3xx) should
	 * be automatically followed.
	 *
	 * @param follow {@code true} if HTTP redirects are automatically
	 *               followed, else {@code false}.
	 */
	public void setFollowRedirects(final boolean follow) {

		followRedirects = follow;
	}
	
	
	/**
	 * Gets the received validated client X.509 certificate for a received
	 * HTTPS request.
	 *
	 * @return The client X.509 certificate, {@code null} if not specified.
	 */
	public X509Certificate getClientX509Certificate() {
		
		return clientX509Certificate;
	}
	
	
	/**
	 * Sets the received validated client X.509 certificate for a received
	 * HTTPS request.
	 *
	 * @param clientX509Certificate The client X.509 certificate,
	 *                              {@code null} if not specified.
	 */
	public void setClientX509Certificate(final X509Certificate clientX509Certificate) {
		
		this.clientX509Certificate = clientX509Certificate;
	}
	
	
	/**
	 * Gets the subject DN of a received validated client X.509 certificate
	 * for a received HTTPS request.
	 *
	 * @return The subject DN, {@code null} if not specified.
	 */
	public String getClientX509CertificateSubjectDN() {
		
		return clientX509CertificateSubjectDN;
	}
	
	
	/**
	 * Sets the subject DN of a received validated client X.509 certificate
	 * for a received HTTPS request.
	 *
	 * @param subjectDN The subject DN, {@code null} if not specified.
	 */
	public void setClientX509CertificateSubjectDN(final String subjectDN) {
		
		this.clientX509CertificateSubjectDN = subjectDN;
	}
	
	
	/**
	 * Gets the root issuer DN of a received validated client X.509
	 * certificate for a received HTTPS request.
	 *
	 * @return The root DN, {@code null} if not specified.
	 */
	public String getClientX509CertificateRootDN() {
		
		return clientX509CertificateRootDN;
	}
	
	
	/**
	 * Sets the root issuer DN of a received validated client X.509
	 * certificate for a received HTTPS request.
	 *
	 * @param rootDN The root DN, {@code null} if not specified.
	 */
	public void setClientX509CertificateRootDN(final String rootDN) {
		
		this.clientX509CertificateRootDN = rootDN;
	}
	
	
	/**
	 * Gets the hostname verifier for outgoing HTTPS requests.
	 *
	 * @return The hostname verifier, {@code null} implies use of the
	 *         {@link #getDefaultHostnameVerifier() default one}.
	 */
	public HostnameVerifier getHostnameVerifier() {
		
		return hostnameVerifier;
	}
	
	
	/**
	 * Sets the hostname verifier for outgoing HTTPS requests.
	 *
	 * @param hostnameVerifier The hostname verifier, {@code null} implies
	 *                         use of the
	 *                         {@link #getDefaultHostnameVerifier() default
	 *                         one}.
	 */
	public void setHostnameVerifier(final HostnameVerifier hostnameVerifier) {
		
		this.hostnameVerifier = hostnameVerifier;
	}
	
	
	/**
	 * Gets the SSL factory for outgoing HTTPS requests.
	 *
	 * @return The SSL factory, {@code null} implies of the default one.
	 */
	public SSLSocketFactory getSSLSocketFactory() {
		
		return sslSocketFactory;
	}
	
	
	/**
	 * Sets the SSL factory for outgoing HTTPS requests. Use the
	 * {@link com.nimbusds.oauth2.sdk.util.tls.TLSUtils TLS utility} to
	 * set a custom trust store for server and CA certificates and / or a
	 * custom key store for client private keys and certificates, also to
	 * select a specific TLS protocol version.
	 *
	 * @param sslSocketFactory The SSL factory, {@code null} implies use of
	 *                         the default one.
	 */
	public void setSSLSocketFactory(final SSLSocketFactory sslSocketFactory) {
		
		this.sslSocketFactory = sslSocketFactory;
	}
	
	
	/**
	 * Returns the default hostname verifier for all outgoing HTTPS
	 * requests.
	 *
	 * @return The hostname verifier.
	 */
	public static HostnameVerifier getDefaultHostnameVerifier() {

		return defaultHostnameVerifier;
	}


	/**
	 * Sets the default hostname verifier for all outgoing HTTPS requests.
	 * Can be overridden on a individual request basis.
	 *
	 * @param defaultHostnameVerifier The hostname verifier. Must not be
	 *                                {@code null}.
	 */
	public static void setDefaultHostnameVerifier(final HostnameVerifier defaultHostnameVerifier) {

		if (defaultHostnameVerifier == null) {
			throw new IllegalArgumentException("The hostname verifier must not be null");
		}

		HTTPRequest.defaultHostnameVerifier = defaultHostnameVerifier;
	}


	/**
	 * Returns the default SSL socket factory for all outgoing HTTPS
	 * requests.
	 *
	 * @return The SSL socket factory.
	 */
	public static SSLSocketFactory getDefaultSSLSocketFactory() {

		return defaultSSLSocketFactory;
	}


	/**
	 * Sets the default SSL socket factory for all outgoing HTTPS requests.
	 * Can be overridden on a individual request basis. Use the
	 * {@link com.nimbusds.oauth2.sdk.util.tls.TLSUtils TLS utility} to
	 * set a custom trust store for server and CA certificates and / or a
	 * custom key store for client private keys and certificates, also to
	 * select a specific TLS protocol version.
	 *
	 * @param sslSocketFactory The SSL socket factory. Must not be
	 *                         {@code null}.
	 */
	public static void setDefaultSSLSocketFactory(final SSLSocketFactory sslSocketFactory) {

		if (sslSocketFactory == null) {
			throw new IllegalArgumentException("The SSL socket factory must not be null");
		}

		HTTPRequest.defaultSSLSocketFactory = sslSocketFactory;
	}


	/**
	 * Returns an established HTTP URL connection for this HTTP request.
	 * Deprecated as of v5.31, use {@link #toHttpURLConnection()} with
	 * {@link #setHostnameVerifier} and {@link #setSSLSocketFactory}
	 * instead.
	 *
	 * @param hostnameVerifier The hostname verifier for outgoing HTTPS
	 *                         requests, {@code null} implies use of the
	 *                         {@link #getDefaultHostnameVerifier() default
	 *                         one}.
	 * @param sslSocketFactory The SSL socket factory for HTTPS requests,
	 *                         {@code null} implies use of the
	 *                         {@link #getDefaultSSLSocketFactory() default
	 *                         one}.
	 *
	 * @return The HTTP URL connection, with the request sent and ready to
	 *         read the response.
	 *
	 * @throws IOException If the HTTP request couldn't be made, due to a
	 *                     network or other error.
	 */
	@Deprecated
	public HttpURLConnection toHttpURLConnection(final HostnameVerifier hostnameVerifier,
						     final SSLSocketFactory sslSocketFactory)
		throws IOException {
		
		HostnameVerifier savedHostnameVerifier = getHostnameVerifier();
		SSLSocketFactory savedSSLFactory = getSSLSocketFactory();
		
		try {
			// Set for this HTTP URL connection only
			setHostnameVerifier(hostnameVerifier);
			setSSLSocketFactory(sslSocketFactory);
			
			return toHttpURLConnection();
			
		} finally {
			setHostnameVerifier(savedHostnameVerifier);
			setSSLSocketFactory(savedSSLFactory);
		}
	}


	/**
	 * Returns an established HTTP URL connection for this HTTP request.
	 *
	 * @return The HTTP URL connection, with the request sent and ready to
	 *         read the response.
	 *
	 * @throws IOException If the HTTP request couldn't be made, due to a
	 *                     network or other error.
	 */
	public HttpURLConnection toHttpURLConnection()
		throws IOException {

		final URL finalURL = getURL();

		HttpURLConnection conn = (HttpURLConnection) (proxy == null ? finalURL.openConnection() : finalURL.openConnection(proxy));

		if (conn instanceof HttpsURLConnection) {
			HttpsURLConnection sslConn = (HttpsURLConnection)conn;
			sslConn.setHostnameVerifier(hostnameVerifier != null ? hostnameVerifier : getDefaultHostnameVerifier());
			sslConn.setSSLSocketFactory(sslSocketFactory != null ? sslSocketFactory : getDefaultSSLSocketFactory());
		}

		for (Map.Entry<String,List<String>> header: getHeaderMap().entrySet()) {
			for (String headerValue: header.getValue()) {
				conn.addRequestProperty(header.getKey(), headerValue);
			}
		}

		conn.setRequestMethod(method.name());
		conn.setConnectTimeout(connectTimeout);
		conn.setReadTimeout(readTimeout);
		conn.setInstanceFollowRedirects(followRedirects);

		if (method.equals(HTTPRequest.Method.POST) || method.equals(Method.PUT)) {

			conn.setDoOutput(true);

			if (getEntityContentType() != null)
				conn.setRequestProperty("Content-Type", getEntityContentType().toString());

			if (getBody() != null) {
				OutputStream outputStream = null;
				try {
                    			outputStream = conn.getOutputStream();
                    			OutputStreamWriter writer = new OutputStreamWriter(outputStream);
					writer.write(getBody());
					writer.close();
				} catch (IOException e) {
					closeStreams(conn.getInputStream(), outputStream, conn.getErrorStream(), debugCloseStreams);
					throw e; // Rethrow
				}
			}
		}

		return conn;
	}


	/**
	 * Sends this HTTP request to the request URL and retrieves the
	 * resulting HTTP response. Deprecated as of v5.31, use
	 * {@link #toHttpURLConnection()} with {@link #setHostnameVerifier} and
	 * {@link #setSSLSocketFactory} instead.
	 *
	 * @param hostnameVerifier The hostname verifier for outgoing HTTPS
	 *                         requests, {@code null} implies use of the
	 *                         {@link #getDefaultHostnameVerifier() default
	 *                         one}.
	 * @param sslSocketFactory The SSL socket factory for HTTPS requests,
	 *                         {@code null} implies use of the
	 *                         {@link #getDefaultSSLSocketFactory() default
	 *                         one}.
	 *
	 * @return The resulting HTTP response.
	 *
	 * @throws IOException If the HTTP request couldn't be made, due to a
	 *                     network or other error.
	 */
	@Deprecated
	public HTTPResponse send(final HostnameVerifier hostnameVerifier,
				 final SSLSocketFactory sslSocketFactory)
		throws IOException {
		
		HostnameVerifier savedHostnameVerifier = getHostnameVerifier();
		SSLSocketFactory savedSSLFactory = getSSLSocketFactory();
		
		try {
			// Set for this HTTP URL connection only
			setHostnameVerifier(hostnameVerifier);
			setSSLSocketFactory(sslSocketFactory);
			
			return send();
			
		} finally {
			setHostnameVerifier(savedHostnameVerifier);
			setSSLSocketFactory(savedSSLFactory);
		}
	}


	/**
	 * Sends this HTTP request to the {@link #getURL() URL} and retrieves
	 * the resulting HTTP response.
	 *
	 * @return The resulting HTTP response.
	 *
	 * @throws IOException If the HTTP request couldn't be sent, due to a
	 *                     network or another error.
	 */
	public HTTPResponse send()
		throws IOException {

		HttpURLConnection conn = toHttpURLConnection();

		int statusCode;

		BufferedReader reader;

		InputStream inputStream = null;
		InputStream errStream = null;
		OutputStream outputStream = null;
		try {
			// getOutputStream() can only be retrieved before calling getInputStream()
			if (conn.getDoOutput()) {
				outputStream = conn.getOutputStream();
			}
			// Open a connection, then send method and headers
			inputStream = conn.getInputStream();
			reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));

			// The next step is to get the status
			statusCode = conn.getResponseCode();

		} catch (IOException e) {

			// HttpUrlConnection will throw an IOException if any
			// 4XX response is sent. If we request the status
			// again, this time the internal status will be
			// properly set, and we'll be able to retrieve it.
			statusCode = conn.getResponseCode();

			if (statusCode == -1) {
				throw e; // Rethrow IO exception
			} else {
				// HTTP status code indicates the response got
				// through, read the content but using error stream
				errStream = conn.getErrorStream();

				if (errStream != null) {
					// We have useful HTTP error body
					reader = new BufferedReader(new InputStreamReader(errStream, StandardCharsets.UTF_8));
				} else {
					// No content, set to empty string
					reader = new BufferedReader(new StringReader(""));
				}
			}
		}

		StringBuilder body = new StringBuilder();
		String line;
		while ((line = reader.readLine()) != null) {
			body.append(line);
			body.append(System.getProperty("line.separator"));
		}
		reader.close();


		HTTPResponse response = new HTTPResponse(statusCode);
		
		response.setStatusMessage(conn.getResponseMessage());

		// Set headers
		for (Map.Entry<String,List<String>> responseHeader: conn.getHeaderFields().entrySet()) {

			if (responseHeader.getKey() == null) {
				continue; // skip header
			}

			List<String> values = responseHeader.getValue();
			if (values == null || values.isEmpty() || values.get(0) == null) {
				continue; // skip header
			}

			response.setHeader(responseHeader.getKey(), values.toArray(new String[]{}));
		}

		closeStreams(inputStream, outputStream, errStream, debugCloseStreams);

		final String bodyContent = body.toString();
		if (! bodyContent.isEmpty())
			response.setBody(bodyContent);

		return response;
	}


	/**
	 * Sends this HTTP request to the {@link #getURL() URL} and retrieves
	 * the resulting HTTP response.
	 *
	 * @param httpRequestSender The HTTP request sender. Must not be
	 *                          {@code null}.
	 *
	 * @return The resulting HTTP response.
	 *
	 * @throws IOException If the HTTP request couldn't be sent, due to a
	 *                     network or another error.
	 */
	public HTTPResponse send(final HTTPRequestSender httpRequestSender)
		throws IOException {

		ReadOnlyHTTPResponse roResponse = httpRequestSender.send(this);

		HTTPResponse response = new HTTPResponse(roResponse.getStatusCode());
		response.setStatusMessage(roResponse.getStatusMessage());
		for (Map.Entry<String, List<String>> en: roResponse.getHeaderMap().entrySet()) {
			if (en.getKey() != null && en.getValue() != null && ! en.getValue().isEmpty()) {
				response.setHeader(en.getKey(), en.getValue().toArray(new String[0]));
			}
		}
		response.setBody(roResponse.getBody());
		return response;
	}


	/**
	 * Closes the input, output and error streams of the specified HTTP URL
	 * connection. No attempt is made to close the underlying socket with
	 * {@code conn.disconnect} so it may be cached (HTTP 1.1 keep live).
	 * See http://techblog.bozho.net/caveats-of-httpurlconnection/
	 */
	private static void closeStreams(final InputStream inputStream,
					 final OutputStream outputStream,
					 final InputStream errStream,
					 final boolean debugCloseStreams)
		throws IOException {

		try {
			if (inputStream != null) {
				inputStream.close();
			}
		} catch (IOException e) {
			if (debugCloseStreams) {
				throw e;
			}
		} catch (Exception e) {
			// ignore
		}

		try {
			if (outputStream != null) {
				outputStream.close();
			}
		} catch (IOException e) {
			if (debugCloseStreams) {
				throw e;
			}
		} catch (Exception e) {
			// ignore
		}

		try {
			if (errStream != null) {
				errStream.close();
			}
		} catch (IOException e) {
			if (debugCloseStreams) {
				throw e;
			}
		} catch (Exception e) {
			// ignore
		}
	}
}

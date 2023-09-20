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


import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;


/**
 * HTTP Servlet utilities.
 *
 * <p>Requires the optional {@code javax.servlet} dependency (or newer):
 *
 * <pre>
 * javax.servlet:javax.servlet-api:3.0.1
 * </pre>
 */
@ThreadSafe
public class ServletUtils {


	/**
	 * Reconstructs the request URL string for the specified servlet
	 * request. The host part is always the local IP address. The query
	 * string and fragment is always omitted.
	 *
	 * @param request The servlet request. Must not be {@code null}.
	 *
	 * @return The reconstructed request URL string.
	 */
	private static String reconstructRequestURLString(final HttpServletRequest request) {

		StringBuilder sb = new StringBuilder("http");

		if (request.isSecure())
			sb.append('s');

		sb.append("://");

		String localAddress = request.getLocalAddr();
		
		if (localAddress == null || localAddress.trim().isEmpty()) {
			// Unknown local address (hostname / IP address)
		} else if (localAddress.contains(".")) {
			// IPv3 address
			sb.append(localAddress);
		} else if (localAddress.contains(":")) {
			
			// IPv6 address, see RFC 2732
			
			// Handle non-compliant "Jetty" formatting of IPv6 address:
			// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/376/
			
			if (! localAddress.startsWith("[")) {
				sb.append('[');
			}
			
			sb.append(localAddress);
			
			if (! localAddress.endsWith("]")) {
				sb.append(']');
			}
		}

		if (! request.isSecure() && request.getLocalPort() != 80) {
			// HTTP plain at port other than 80
			sb.append(':');
			sb.append(request.getLocalPort());
		}

		if (request.isSecure() && request.getLocalPort() != 443) {
			// HTTPS at port other than 443 (default TLS)
			sb.append(':');
			sb.append(request.getLocalPort());
		}

		String path = request.getRequestURI();

		if (path != null)
			sb.append(path);

		return sb.toString();
	}


	/**
	 * Creates a new HTTP request from the specified HTTP servlet request.
	 *
	 * <p><strong>Warning about servlet filters: </strong> Processing of
	 * HTTP POST and PUT requests requires the entity body to be available
	 * for reading from the {@link HttpServletRequest}. If you're getting
	 * unexpected exceptions, please ensure the entity body is not consumed
	 * or modified by an upstream servlet filter.
	 *
	 * @param sr The servlet request. Must not be {@code null}.
	 *
	 * @return The HTTP request.
	 *
	 * @throws IllegalArgumentException The the servlet request method is
	 *                                  not GET, POST, PUT or DELETE or the
	 *                                  content type header value couldn't
	 *                                  be parsed.
	 * @throws IOException              For a POST or PUT body that
	 *                                  couldn't be read due to an I/O
	 *                                  exception.
	 */
	public static HTTPRequest createHTTPRequest(final HttpServletRequest sr)
		throws IOException {

		return createHTTPRequest(sr, -1);
	}


	/**
	 * Creates a new HTTP request from the specified HTTP servlet request.
	 *
	 * <p><strong>Warning about servlet filters: </strong> Processing of
	 * HTTP POST and PUT requests requires the entity body to be available
	 * for reading from the {@link HttpServletRequest}. If you're getting
	 * unexpected exceptions, please ensure the entity body is not consumed
	 * or modified by an upstream servlet filter.
	 *
	 * @param sr              The servlet request. Must not be
	 *                        {@code null}.
	 * @param maxEntityLength The maximum entity length to accept, -1 for
	 *                        no limit.
	 *
	 * @return The HTTP request.
	 *
	 * @throws IllegalArgumentException The the servlet request method is
	 *                                  not GET, POST, PUT or DELETE or the
	 *                                  content type header value couldn't
	 *                                  be parsed.
	 * @throws IOException              For a POST or PUT body that
	 *                                  couldn't be read due to an I/O
	 *                                  exception.
	 */
	public static HTTPRequest createHTTPRequest(final HttpServletRequest sr, final long maxEntityLength)
		throws IOException {

		HTTPRequest.Method method = HTTPRequest.Method.valueOf(sr.getMethod().toUpperCase());

		String urlString = reconstructRequestURLString(sr);

		URL url;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid request URL: " + e.getMessage() + ": " + urlString, e);
		}

		HTTPRequest request = new HTTPRequest(method, url);

		try {
			request.setContentType(sr.getContentType());

		} catch (ParseException e) {

			throw new IllegalArgumentException("Invalid Content-Type header value: " + e.getMessage(), e);
		}

		Enumeration<String> headerNames = sr.getHeaderNames();

		while (headerNames.hasMoreElements()) {
			
			final String headerName = headerNames.nextElement();
			
			Enumeration<String> headerValues = sr.getHeaders(headerName);
			
			if (headerValues == null || ! headerValues.hasMoreElements())
				continue;
			
			List<String> headerValuesList = new LinkedList<>();
			while (headerValues.hasMoreElements()) {
				headerValuesList.add(headerValues.nextElement());
			}
			
			request.setHeader(headerName, headerValuesList.toArray(new String[0]));
		}

		if (method.equals(HTTPRequest.Method.GET) || method.equals(HTTPRequest.Method.DELETE)) {

			request.setQuery(sr.getQueryString());

		} else if (method.equals(HTTPRequest.Method.POST) || method.equals(HTTPRequest.Method.PUT)) {

			// Impossible to read application/x-www-form-urlencoded request content on which parameters
			// APIs have been used. To be safe we recreate the content based on the parameters in this case.
			// See issues
			// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/184
			// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/186
			if (ContentType.APPLICATION_URLENCODED.matches(request.getEntityContentType())) {

				// Recreate the content based on parameters
				request.setQuery(URLUtils.serializeParametersAlt(sr.getParameterMap()));
			} else {
				// read body
				StringBuilder body = new StringBuilder(256);

				BufferedReader reader = sr.getReader();

				char[] cbuf = new char[256];

				int readChars;

				while ((readChars = reader.read(cbuf)) != -1) {

					body.append(cbuf, 0, readChars);

					if (maxEntityLength > 0 && body.length() > maxEntityLength) {
						throw new IOException(
							"Request entity body is too large, limit is " + maxEntityLength + " chars");
					}
				}

				reader.close();
				request.setQuery(body.toString());
			}
		}
		
		// Extract validated client X.509 if we have mutual TLS
		X509Certificate cert = extractClientX509Certificate(sr);
		if (cert != null) {
			request.setClientX509Certificate(cert);
			request.setClientX509CertificateSubjectDN(cert.getSubjectDN() != null ? cert.getSubjectDN().getName() : null);
			
			// The root DN cannot be reliably set for a CA-signed
			// client cert from a servlet request, unless self-issued
			if (X509CertificateUtils.hasMatchingIssuerAndSubject(cert)) {
				request.setClientX509CertificateRootDN(cert.getIssuerDN() != null ? cert.getIssuerDN().getName() : null);
			}
		}
		
		// Extract client IP address, X-Forwarded-For not checked
		request.setClientIPAddress(sr.getRemoteAddr());

		return request;
	}


	/**
	 * Applies the status code, headers and content of the specified HTTP
	 * response to a HTTP servlet response.
	 *
	 * @param httpResponse    The HTTP response. Must not be {@code null}.
	 * @param servletResponse The HTTP servlet response. Must not be
	 *                        {@code null}.
	 *
	 * @throws IOException If the response content couldn't be written.
	 */
	public static void applyHTTPResponse(final HTTPResponse httpResponse,
					     final HttpServletResponse servletResponse)
		throws IOException {

		// Set the status code
		servletResponse.setStatus(httpResponse.getStatusCode());


		// Set the headers, but only if explicitly specified
		for (Map.Entry<String,List<String>> header : httpResponse.getHeaderMap().entrySet()) {
			for (String headerValue: header.getValue()) {
				servletResponse.addHeader(header.getKey(), headerValue);
			}
		}

		if (httpResponse.getEntityContentType() != null)
			servletResponse.setContentType(httpResponse.getEntityContentType().toString());


		// Write out the content

		if (httpResponse.getContent() != null) {

			PrintWriter writer = servletResponse.getWriter();
			writer.print(httpResponse.getContent());
			writer.close();
		}
	}
	
	
	/**
	 * Extracts the client's X.509 certificate from the specified servlet
	 * request. The first found certificate is returned, if any.
	 *
	 * @param servletRequest The HTTP servlet request. Must not be
	 *                       {@code null}.
	 *
	 * @return The first client X.509 certificate, {@code null} if none is
	 *         found.
	 */
	public static X509Certificate extractClientX509Certificate(final ServletRequest servletRequest) {
		
		X509Certificate[] certs = (X509Certificate[]) servletRequest.getAttribute("javax.servlet.request.X509Certificate");
		
		if (certs == null || certs.length == 0) {
			return null;
		}
		
		return certs[0];
	}


	/**
	 * Prevents public instantiation.
	 */
	private ServletUtils() { }
}

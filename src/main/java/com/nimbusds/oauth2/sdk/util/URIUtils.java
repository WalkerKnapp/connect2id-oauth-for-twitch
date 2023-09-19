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

package com.nimbusds.oauth2.sdk.util;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;


/**
 * URI operations.
 */
public final class URIUtils {


	/**
	 * Gets the base part (schema, host, port and path) of the specified
	 * URI.
	 *
	 * @param uri The URI. May be {@code null}.
	 *
	 * @return The base part of the URI, {@code null} if the original URI
	 *         is {@code null} or doesn't specify a protocol.
	 */
	public static URI getBaseURI(final URI uri) {

		if (uri == null)
			return null;

		try {
			return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, null);

		} catch (URISyntaxException e) {

			return null;
		}
	}
	
	
	/**
	 * Prepends the specified path component to a URI. The prepended and
	 * any existing path component are always joined with a single slash
	 * ('/') between them
	 *
	 * @param uri           The URI, {@code null} if not specified.
	 * @param pathComponent The path component to prepend, {@code null} if
	 *                      not specified.
	 *
	 * @return The URI with prepended path component, {@code null} if the
	 *         original URI wasn't specified.
	 */
	public static URI prependPath(final URI uri, final String pathComponent) {
		
		if (uri == null) {
			return null;
		}
		
		if (StringUtils.isBlank(pathComponent)) {
			return uri;
		}
		
		String origPath = uri.getPath();
		if (origPath == null || origPath.isEmpty() || origPath.equals("/")) {
			origPath = null;
		}
		String joinedPath = joinPathComponents(pathComponent, origPath);
		joinedPath = prependLeadingSlashIfMissing(joinedPath);
		
		try {
			return new URI(
				uri.getScheme(), null, uri.getHost(), uri.getPort(),
				joinedPath,
				uri.getQuery(), uri.getFragment());
		} catch (URISyntaxException e) {
			// should never happen when starting from a legal URI
			return null;
		}
	}
	
	
	/**
	 * Prepends a leading slash `/` if missing to the specified string.
	 *
	 * @param s The string, {@code null} if not specified.
	 *
	 * @return The string with leading slash, {@code null} if not
	 *         originally specified.
	 */
	public static String prependLeadingSlashIfMissing(String s) {
		if (s == null) {
			return null;
		}
		if (s.startsWith("/")) {
			return s;
		}
		return "/" + s;
	}
	
	
	/**
	 * Strips any leading slashes '/' if present from the specified string.
	 *
	 * @param s The string, {@code null} if not specified.
	 *
	 * @return The string with no leading slash, {@code null} if not
	 *         originally specified.
	 */
	public static String stripLeadingSlashIfPresent(final String s) {
		if (StringUtils.isBlank(s)) {
			return s;
		}
		if (s.startsWith("/")) {
			String tmp = s;
			while (tmp.startsWith("/")) {
				tmp = tmp.substring(1);
			}
			return tmp;
		}
		return s;
	}
	
	
	/**
	 * Joins two path components. If the two path components are not
	 * {@code null} or empty they are joined so that there is only a single
	 * slash ('/') between them.
	 *
	 * @param c1 The first path component, {@code null} if not specified.
	 * @param c2 The second path component, {@code null} if not specified.
	 *
	 * @return The joined path components, {@code null} if both are not
	 *         specified, or if one is {@code null} the other unmodified.
	 */
	public static String joinPathComponents(final String c1, final String c2) {
		
		if (c1 == null && c2 == null) {
			return null;
		}
		
		if (c1 == null || c1.isEmpty()) {
			return c2;
		}
		
		if (c2 == null || c2.isEmpty()) {
			return c1;
		}
		
		if (c1.endsWith("/") && ! c2.startsWith("/")) {
			return c1 + c2;
		}
		if (! c1.endsWith("/") && c2.startsWith("/")) {
			return c1 + c2;
		}
		if (c1.endsWith("/") && c2.startsWith("/")) {
			return c1 + stripLeadingSlashIfPresent(c2);
		}
		return c1 + "/" + c2;
	}
	
	
	/**
	 * Strips the query string from the specified URI.
	 *
	 * @param uri The URI. May be {@code null}.'
	 *
	 * @return The URI with stripped query string, {@code null} if the
	 *         original URI is {@code null} or doesn't specify a protocol.
	 */
	public static URI stripQueryString(final URI uri) {
		
		if (uri == null)
			return null;
		
		try {
			return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, uri.getFragment());
			
		} catch (URISyntaxException e) {
			return null;
		}
	}
	
	
	/**
	 * Removes the trailing slash ("/") from the specified URI, if present.
	 *
	 * @param uri The URI. May be {@code null}.
	 *
	 * @return The URI with no trailing slash, {@code null} if the original
	 *         URI is {@code null}.
	 */
	public static URI removeTrailingSlash(final URI uri) {
		
		if (uri == null)
			return null;
		
		String uriString = uri.toString();
		
		if (uriString.charAt(uriString.length() - 1 ) == '/') {
			return URI.create(uriString.substring(0, uriString.length() - 1));
		}
		
		return uri;
	}
	
	
	/**
	 * Ensures the scheme of the specified URI is https.
	 *
	 * @param uri The URI to check, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the URI is specified and the
	 *                                  scheme is not https.
	 */
	public static void ensureSchemeIsHTTPS(final URI uri) {
		
		if (uri == null) {
			return;
		}
		
		if (uri.getScheme() == null || ! "https".equalsIgnoreCase(uri.getScheme())) {
			throw new IllegalArgumentException("The URI scheme must be https");
		}
	}
	
	
	/**
	 * Ensures the scheme of the specified URI is https or http.
	 *
	 * @param uri The URI to check, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the URI is specified and the
	 *                                  scheme is not https or http.
	 */
	public static void ensureSchemeIsHTTPSorHTTP(final URI uri) {
		
		if (uri == null) {
			return;
		}
		
		if (uri.getScheme() == null || ! Arrays.asList("http", "https").contains(uri.getScheme().toLowerCase())) {
			throw new IllegalArgumentException("The URI scheme must be https or http");
		}
	}
	
	
	/**
	 * Ensures the scheme of the specified URI is not prohibited.
	 *
	 * @param uri                  The URI to check, {@code null} if not
	 *                             specified.
	 * @param prohibitedURISchemes The prohibited URI schemes (should be in
	 *                             lower case), empty or {@code null} if
	 *                             not specified.
	 *
	 * @throws IllegalArgumentException If the URI is specified and its
	 *                                  scheme is prohibited.
	 */
	public static void ensureSchemeIsNotProhibited(final URI uri, final Set<String> prohibitedURISchemes) {
		
		if (uri == null || uri.getScheme() == null || prohibitedURISchemes == null || prohibitedURISchemes.isEmpty()) {
			return;
		}
		
		if (prohibitedURISchemes.contains(uri.getScheme().toLowerCase())) {
			throw new IllegalArgumentException("The URI scheme " + uri.getScheme() + " is prohibited");
		}
	}


	/**
	 * Ensures the query of the specified URI is not prohibited.
	 *
	 * @param uri                       The URI to check, {@code null} if
	 *                                  not specified.
	 * @param prohibitedQueryParamNames The prohibited query parameter
	 *                                  names, empty or {@code null} if not
	 *                                  specified.
	 *
	 * @throws IllegalArgumentException If the URI is specified and
	 *                                  includes prohibited query parameter
	 *                                  names.
	 */
	public static void ensureQueryIsNotProhibited(final URI uri, final Set<String> prohibitedQueryParamNames) {

		if (uri == null || uri.getQuery() == null || uri.getQuery().isEmpty() || prohibitedQueryParamNames == null || prohibitedQueryParamNames.isEmpty()) {
			return;
		}

		Map<String, List<String>> params = URLUtils.parseParameters(uri.getQuery());

		for (String paramName: params.keySet()) {
			if (prohibitedQueryParamNames.contains(paramName)) {
				throw new IllegalArgumentException("The query parameter " + paramName + " is prohibited");
			}
		}
	}
	
	
	/**
	 * Returns a string list representation of the specified URI
	 * collection. Collection items that are {@code null} are not returned.
	 *
	 * @param uriList The URI collection, {@code null} if not specified.
	 *
	 * @return The string list, {@code null} if not specified.
	 */
	public static List<String> toStringList(final Collection<URI> uriList) {
		
		return toStringList(uriList, true);
	}
	
	
	/**
	 * Returns a string list representation of the specified URI
	 * collection.
	 *
	 * @param uriList     The URI collection, {@code null} if not
	 *                    specified.
	 * @param ignoreNulls {@code true} to not include {@code null} values.
	 *
	 * @return The string list, {@code null} if not specified.
	 */
	public static List<String> toStringList(final Collection<URI> uriList, final boolean ignoreNulls) {
		
		if (uriList == null) {
			return null;
		}
		
		if (uriList.isEmpty()) {
			return Collections.emptyList();
		}
		
		List<String> out = new LinkedList<>();
		for (URI uri: uriList) {
			if (uri != null) {
				out.add(uri.toString());
			} else if (! ignoreNulls) {
				out.add(null);
			}
		}
		return out;
	}


	/**
	 * Prevents public instantiation.
	 */
	private URIUtils() {}
}

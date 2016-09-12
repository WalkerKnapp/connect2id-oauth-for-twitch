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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.mail.internet.ContentType;
import javax.mail.internet.ParseException;

import net.jcip.annotations.ThreadSafe;
import org.apache.commons.io.input.BoundedInputStream;


/**
 * The default retriever of resources specified by URL. Provides setting of
 * HTTP connect and read timeouts as well as a size limit of the retrieved
 * entity. Caching header directives are not honoured.
 */
@ThreadSafe
@Deprecated
public class DefaultResourceRetriever extends AbstractRestrictedResourceRetriever implements RestrictedResourceRetriever {


	/**
	 * The system line separator.
	 */
	private final String lineSeparator;
	
	
	/**
	 * Creates a new resource retriever. The HTTP timeouts and entity size
	 * limit are set to zero (infinite).
	 */
	public DefaultResourceRetriever() {
	
		this(0, 0);	
	}
	
	
	/**
	 * Creates a new resource retriever. The HTTP entity size limit is set
	 * to zero (infinite).
	 *
	 * @param connectTimeout The HTTP connects timeout, in milliseconds, 
	 *                       zero for infinite. Must not be negative.
	 * @param readTimeout    The HTTP read timeout, in milliseconds, zero 
	 *                       for infinite. Must not be negative.
	 */
	public DefaultResourceRetriever(final int connectTimeout, final int readTimeout) {

		this(connectTimeout, readTimeout, 0);
	}


	/**
	 * Creates a new resource retriever.
	 *
	 * @param connectTimeout The HTTP connects timeout, in milliseconds,
	 *                       zero for infinite. Must not be negative.
	 * @param readTimeout    The HTTP read timeout, in milliseconds, zero
	 *                       for infinite. Must not be negative.
	 * @param sizeLimit      The HTTP entity size limit, in bytes, zero for
	 *                       infinite. Must not be negative.
	 */
	public DefaultResourceRetriever(final int connectTimeout, final int readTimeout, final int sizeLimit) {
	
		super(connectTimeout, readTimeout, sizeLimit);
		lineSeparator = System.getProperty("line.separator");
	}


	@Override
	public Resource retrieveResource(final URL url)
		throws IOException {
		
		HttpURLConnection con;
		try {
			con = (HttpURLConnection)url.openConnection();
		} catch (ClassCastException e) {
			throw new IOException("Couldn't open HTTP(S) connection: " + e.getMessage(), e);
		}

		con.setConnectTimeout(getConnectTimeout());
		con.setReadTimeout(getReadTimeout());

		StringBuilder sb = new StringBuilder();

		InputStream inputStream = con.getInputStream();

		if (getSizeLimit() > 0) {
			inputStream = new BoundedInputStream(inputStream, getSizeLimit());
		}

		BufferedReader input = new BufferedReader(new InputStreamReader(inputStream));

		String line;

		while ((line = input.readLine()) != null) {

			sb.append(line);
			sb.append(lineSeparator);
		}

		input.close();

		// Check HTTP code + message
		final int statusCode = con.getResponseCode();
		final String statusMessage = con.getResponseMessage();

		// Ensure 2xx status code
		if (statusCode > 299 || statusCode < 200) {
			throw new IOException("HTTP " + statusCode + ": " + statusMessage);
		}

		// Parse the Content-Type header
		ContentType contentType = null;

		if (con.getContentType() != null) {
			try {
				contentType = new ContentType(con.getContentType());
			} catch (ParseException e) {
				throw new IOException("Couldn't parse Content-Type header: " + e.getMessage(), e);
			}
		}
		
		return new Resource(sb.toString(), contentType);
	}
}

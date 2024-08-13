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

package com.nimbusds.oauth2.sdk.assertions.saml2;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import net.jcip.annotations.ThreadSafe;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;


/**
 * SAML 2.0 assertion validator. Supports RSA signatures and HMAC. Provides
 * static methods for each validation step for putting together tailored
 * assertion validation strategies.
 */
@ThreadSafe
public class SAML2AssertionValidator {


	/**
	 * The SAML 2.0 assertion details verifier.
	 */
	private final SAML2AssertionDetailsVerifier detailsVerifier;


	static {
		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}


	/**
	 * Creates a new SAML 2.0 assertion validator.
	 *
	 * @param detailsVerifier The SAML 2.0 assertion details verifier. Must
	 *                        not be {@code null}.
	 */
	public SAML2AssertionValidator(final SAML2AssertionDetailsVerifier detailsVerifier) {
		this.detailsVerifier = Objects.requireNonNull(detailsVerifier);
	}


	/**
	 * Gets the SAML 2.0 assertion details verifier.
	 *
	 * @return The SAML 2.0 assertion details verifier.
	 */
	public SAML2AssertionDetailsVerifier getDetailsVerifier() {
		return detailsVerifier;
	}


	/**
	 * Parses a SAML 2.0 assertion from the specified XML string.
	 *
	 * @param xml The XML string. Must not be {@code null}.
	 *
	 * @return The SAML 2.0 assertion.
	 *
	 * @throws ParseException If parsing of the assertion failed.
	 */
	public static Assertion parse(final String xml)
		throws ParseException {

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		
		// Disable access to external entities in XML parsing
		documentBuilderFactory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
		documentBuilderFactory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
		
		documentBuilderFactory.setNamespaceAware(true);

		XMLObject xmlObject;

		try {
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

			Document document = docBuilder.parse(new InputSource(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))));
			Element element = document.getDocumentElement();

			xmlObject = XMLObjectProviderRegistrySupport
				.getUnmarshallerFactory()
				.getUnmarshaller(element)
				.unmarshall(element);

		} catch (ParserConfigurationException | IOException | SAXException | UnmarshallingException e) {
			throw new ParseException("SAML 2.0 assertion parsing failed: " + e.getMessage(), e);
		}

		if (! (xmlObject instanceof Assertion)) {
			throw new ParseException("Top-level XML element not a SAML 2.0 assertion");
		}

		return (Assertion)xmlObject;
	}


	/**
	 * Verifies the specified XML signature (HMAC, RSA or EC) with the
	 * provided key.
	 *
	 * @param signature The XML signature. Must not be {@code null}.
	 * @param key       The key to verify the signature. Should be an
	 *                  {@link SecretKey} instance for HMAC,
	 *                  {@link RSAPublicKey} for RSA signatures or
	 *                  {@link ECPublicKey} for EC signatures. Must not be
	 *                  {@code null}.
	 *
	 * @throws BadSAML2AssertionException If the key type doesn't match the
	 *                                    signature, or the signature is
	 *                                    invalid.
	 */
	public static void verifySignature(final Signature signature, final Key key)
		throws BadSAML2AssertionException {

		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		try {
			profileValidator.validate(signature);
		} catch (SignatureException e) {
			throw new BadSAML2AssertionException("Invalid SAML 2.0 signature format: " + e.getMessage(), e);
		}
		
		final BasicCredential credential;
		if (key instanceof SecretKey) {
			credential = new BasicCredential((SecretKey)key);
		} else if (key instanceof PublicKey) {
			credential = new BasicCredential((PublicKey)key);
			credential.setUsageType(UsageType.SIGNING);
		} else {
			throw new BadSAML2AssertionException("Unsupported key type: " + key.getAlgorithm());
		}

		try {
			SignatureValidator.validate(signature, credential);
		} catch (SignatureException e) {
			throw new BadSAML2AssertionException("Bad SAML 2.0 signature: " + e.getMessage(), e);
		}
	}


	/**
	 * Validates the specified SAML 2.0 assertion.
	 *
	 * @param assertion      The SAML 2.0 assertion XML. Must not be
	 *                       {@code null}.
	 * @param expectedIssuer The expected issuer. Must not be {@code null}.
	 * @param key            The key to verify the signature. Should be an
	 *                       {@link SecretKey} instance for HMAC,
	 *                       {@link RSAPublicKey} for RSA signatures or
	 *                       {@link ECPublicKey} for EC signatures. Must
	 *                       not be {@code null}.
	 *
	 * @return The validated SAML 2.0 assertion.
	 *
	 * @throws BadSAML2AssertionException If the assertion is invalid.
	 */
	public Assertion validate(final Assertion assertion,
				  final Issuer expectedIssuer,
				  final Key key)
		throws BadSAML2AssertionException {

		final SAML2AssertionDetails assertionDetails;

		try {
			assertionDetails = SAML2AssertionDetails.parse(assertion);
		} catch (ParseException e) {
			throw new BadSAML2AssertionException("Invalid SAML 2.0 assertion: " + e.getMessage(), e);
		}

		// Check the audience and time window details
		detailsVerifier.verify(assertionDetails);

		// Check the issuer
		if (! expectedIssuer.equals(assertionDetails.getIssuer())) {
			throw new BadSAML2AssertionException("Unexpected issuer: " + assertionDetails.getIssuer());
		}

		if (! assertion.isSigned()) {
			throw new BadSAML2AssertionException("Missing XML signature");
		}

		// Verify the signature
		verifySignature(assertion.getSignature(), key);

		return assertion; // OK
	}


	/**
	 * Validates the specified SAML 2.0 assertion.
	 *
	 * @param xml            The SAML 2.0 assertion XML. Must not be
	 *                       {@code null}.
	 * @param expectedIssuer The expected issuer. Must not be {@code null}.
	 * @param key            The key to verify the signature. Should be an
	 *                       {@link SecretKey} instance for HMAC,
	 *                       {@link RSAPublicKey} for RSA signatures or
	 *                       {@link ECPublicKey} for EC signatures. Must
	 *                       not be {@code null}.
	 *
	 * @return The validated SAML 2.0 assertion.
	 *
	 * @throws BadSAML2AssertionException If the assertion is invalid.
	 */
	public Assertion validate(final String xml,
				  final Issuer expectedIssuer,
				  final Key key)
		throws BadSAML2AssertionException {

		// Parse string to XML, then to SAML 2.0 assertion object
		final Assertion assertion;

		try {
			assertion = parse(xml);
		} catch (ParseException e) {
			throw new BadSAML2AssertionException("Invalid SAML 2.0 assertion: " + e.getMessage(), e);
		}

		return validate(assertion, expectedIssuer, key);
	}
}

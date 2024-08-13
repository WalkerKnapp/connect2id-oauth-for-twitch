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


import com.nimbusds.oauth2.sdk.SerializeException;
import net.jcip.annotations.ThreadSafe;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static com.nimbusds.oauth2.sdk.assertions.saml2.SAML2Utils.buildSAMLObject;
import static net.shibboleth.utilities.java.support.xml.SerializeSupport.nodeToString;


/**
 * Static SAML 2.0 bearer assertion factory.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521)
 *     <li>Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0
 *         Client Authentication and Authorization Grants (RFC 7522)
 * </ul>
 */
@ThreadSafe
public class SAML2AssertionFactory {


	/**
	 * Creates a new SAML 2.0 assertion.
	 *
	 * @param details    The SAML 2.0 bearer assertion details. Must not
	 *                   be {@code null}.
	 * @param xmlDsigAlg The XML digital signature algorithm. Must not be
	 *                   {@code null}.
	 * @param credential The appropriate credentials to facilitate signing
	 *                   of the assertion.
	 *
	 * @return The SAML 2.0 bearer assertion.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static Assertion create(final SAML2AssertionDetails details,
				       final String xmlDsigAlg,
				       final Credential credential) {

		Assertion a = details.toSAML2Assertion();

		// Create signature element
		Signature signature = buildSAMLObject(Signature.class);
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(xmlDsigAlg);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		a.setSignature(signature);
		
		try {
			// Marshall and sign
			XMLObjectProviderRegistrySupport
				.getMarshallerFactory()
				.getMarshaller(a)
				.marshall(a);
			Signer.signObject(signature);
		} catch (MarshallingException | SignatureException e) {
			throw new SerializeException(e.getMessage(), e);
		}

		return a;
	}


	/**
	 * Creates a new SAML 2.0 assertion as an XML element.
	 *
	 * @param details    The SAML 2.0 bearer assertion details. Must not
	 *                   be {@code null}.
	 * @param xmlDsigAlg The XML digital signature algorithm. Must not be
	 *                   {@code null}.
	 * @param credential The appropriate credentials to facilitate signing
	 *                   of the assertion.
	 *
	 * @return The SAML 2.0 bearer assertion as an XML element.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static Element createAsElement(final SAML2AssertionDetails details,
					      final String xmlDsigAlg,
					      final Credential credential) {

		Assertion a = create(details, xmlDsigAlg, credential);
		try {
			return XMLObjectProviderRegistrySupport
				.getMarshallerFactory()
				.getMarshaller(a)
				.marshall(a);
		} catch (MarshallingException e) {
			throw new SerializeException(e.getMessage(), e);
		}
	}


	/**
	 * Creates a new SAML 2.0 assertion as an XML string.
	 *
	 * @param details    The SAML 2.0 bearer assertion details. Must not
	 *                   be {@code null}.
	 * @param xmlDsigAlg The XML digital signature algorithm. Must not be
	 *                   {@code null}.
	 * @param credential The appropriate credentials to facilitate signing
	 *                   of the assertion.
	 *
	 * @return The SAML 2.0 bearer assertion as an XML string. Note that
	 *         an XML declaration is not present in the output string.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static String createAsString(final SAML2AssertionDetails details,
					    final String xmlDsigAlg,
					    final Credential credential) {

		Element a = createAsElement(details, xmlDsigAlg, credential);
		String xml = nodeToString(a);
		
		// Strip XML doc declaration
		final String header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
		if (xml.startsWith(header)) {
			xml = xml.substring(header.length());
		}
		
		return xml;
	}


	/**
	 * Creates a new SAML 2.0 assertion as an XML string, signed with the
	 * RSA-SHA256 XML digital signature algorithm (mandatory to implement).
	 *
	 * @param details       The SAML 2.0 bearer assertion details. Must not
	 *                      be {@code null}.
	 * @param rsaPublicKey  The public RSA key. Must not be {@code null}.
	 * @param rsaPrivateKey The private RSA key to sign the assertion. Must
	 *                      not be {@code null}.
	 *
	 * @return The SAML 2.0 bearer assertion as an XML string. Note that
	 *         an XML declaration is not present in the output string.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static String createAsString(final SAML2AssertionDetails details,
					    final RSAPublicKey rsaPublicKey,
					    final RSAPrivateKey rsaPrivateKey) {

		BasicCredential credential = new BasicCredential(rsaPublicKey, rsaPrivateKey);
		credential.setUsageType(UsageType.SIGNING);
		return createAsString(details, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, credential);
	}


	/**
	 * Prevents public instantiation.
	 */
	private SAML2AssertionFactory() {}
}

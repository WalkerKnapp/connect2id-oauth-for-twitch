package com.nimbusds.oauth2.sdk.tokenexchange;


import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessToken;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.Immutable;

import java.util.*;


/**
 * OAuth 2.0 token exchange grant.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Exchange (RFC 8693)
 * </ul>
 */
@Immutable
public class TokenExchangeGrant extends AuthorizationGrant {
	
	
	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.TOKEN_EXCHANGE;
	
	
	/**
	 * The subject token representing the identity of the party on behalf
	 * of whom the request is being made.
	 */
	private final Token subjectToken;
	
	
	/**
	 * Identifier for the type of the subject token.
	 */
	private final TokenTypeURI subjectTokenType;
	
	
	/**
	 * Optional token representing the identity of the acting party.
	 */
	private final Token actorToken;
	
	
	/**
	 * Identifier for the type of the actor token, if present.
	 */
	private final TokenTypeURI actorTokenType;
	
	
	/**
	 * Optional identifier for the requested type of security token.
	 */
	private final TokenTypeURI requestedTokenType;
	
	
	/**
	 * Optional audience for the requested security token.
	 */
	private final List<Audience> audience;
	
	
	/**
	 * Creates a new token exchange grant.
	 *
	 * @param subjectToken     The subject token representing the identity
	 *                         of the party on behalf of whom the request
	 *                         is being made. Must not be {@code null}.
	 * @param subjectTokenType Identifier for the type of the subject
	 *                         token. Must not be {@code null}.
	 */
	public TokenExchangeGrant(final Token subjectToken,
				  final TokenTypeURI subjectTokenType) {
		
		this(subjectToken, subjectTokenType, null, null, null, null);
	}
	
	
	/**
	 * Creates a new token exchange grant.
	 *
	 * @param subjectToken       The subject token representing the
	 *                           identity of the party on behalf of whom
	 *                           the request is being made. Must not be
	 *                           {@code null}.
	 * @param subjectTokenType   Identifier for the type of the subject
	 *                           token. Must not be {@code null}.
	 * @param actorToken         Optional token representing the identity
	 *                           of the acting party, {@code null} if not
	 *                           specified.
	 * @param actorTokenType     Identifier for the type of the actor
	 *                           token, if present.
	 * @param requestedTokenType Optional identifier for the requested type
	 *                           of security token, {@code null} if not
	 *                           specified.
	 * @param audience           Optional audience for the requested
	 *                           security token, {@code null} if not
	 *                           specified.
	 */
	public TokenExchangeGrant(final Token subjectToken,
				  final TokenTypeURI subjectTokenType,
				  final Token actorToken,
				  final TokenTypeURI actorTokenType,
				  final TokenTypeURI requestedTokenType,
				  final List<Audience> audience) {
		
		super(GRANT_TYPE);
		this.subjectToken = Objects.requireNonNull(subjectToken);
		this.subjectTokenType = Objects.requireNonNull(subjectTokenType);
		this.actorToken = actorToken;
		
		if (actorToken != null && actorTokenType == null) {
			throw new IllegalArgumentException("If an actor token is specified the actor token type must not be null");
		}
		this.actorTokenType = actorTokenType;
		
		this.requestedTokenType = requestedTokenType;
		this.audience = audience;
	}
	
	
	/**
	 * Returns the subject token representing the identity of the party on
	 * behalf of whom the request is being made.
	 *
	 * @return The subject token, {@code null} if not specified.
	 */
	public Token getSubjectToken() {
		
		return subjectToken;
	}
	
	
	/**
	 * Returns the identifier for the type of the subject token.
	 *
	 * @return The subject token type identifier.
	 */
	public TokenTypeURI getSubjectTokenType() {
		
		return subjectTokenType;
	}
	
	
	/**
	 * Returns the optional token representing the identity of the acting
	 * party.
	 *
	 * @return The actor token, {@code null} if not specified.
	 */
	public Token getActorToken() {
		
		return actorToken;
	}
	
	
	/**
	 * Returns the identifier for the type of the optional actor token, if
	 * present.
	 *
	 * @return The actor token type identifier, {@code null} if not
	 *         present.
	 */
	public TokenTypeURI getActorTokenType() {
		
		return actorTokenType;
	}
	
	
	/**
	 * Returns the optional identifier for the requested type of security
	 * token.
	 *
	 * @return The requested token type, {@code null} if not specified.
	 */
	public TokenTypeURI getRequestedTokenType() {
		
		return requestedTokenType;
	}
	
	
	/**
	 * Returns the optional audience for the requested security token.
	 *
	 * @return The audience, {@code null} if not specified.
	 */
	public List<Audience> getAudience() {
		
		return audience;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {
		
		Map<String, List<String>> params = new LinkedHashMap<>();
		
		params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
		
		if (CollectionUtils.isNotEmpty(audience)) {
			params.put("audience", Audience.toStringList(audience));
		}
		
		if (requestedTokenType != null) {
			params.put("requested_token_type", Collections.singletonList(requestedTokenType.getURI().toString()));
		}
		
		params.put("subject_token", Collections.singletonList(subjectToken.getValue()));
		params.put("subject_token_type", Collections.singletonList(subjectTokenType.getURI().toString()));
		
		if (actorToken != null) {
			params.put("actor_token", Collections.singletonList(actorToken.getValue()));
			params.put("actor_token_type", Collections.singletonList(actorTokenType.getURI().toString()));
		}
		
		return params;
	}
	
	
	private static List<Audience> parseAudience(final Map<String, List<String>> params) {
		
		List<String> audienceList = params.get("audience");
		
		if (CollectionUtils.isEmpty(audienceList)) {
			return null;
		}
		
		return Audience.create(audienceList);
	}
	
	
	private static TokenTypeURI parseTokenType(final Map<String, List<String>> params, final String key, final boolean mandatory)
		throws ParseException {
		
		String tokenTypeString = MultivaluedMapUtils.getFirstValue(params, key);
		
		if (StringUtils.isBlank(tokenTypeString)) {
			if (mandatory) {
				String msg = String.format("Missing or empty %s parameter", key);
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			} else {
				return null;
			}
		}
		
		try {
			return TokenTypeURI.parse(tokenTypeString);
		} catch (ParseException uriSyntaxException) {
			String msg = "Invalid " + key + " " + tokenTypeString;
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}
	}
	
	
	private static TypelessToken parseToken(final Map<String, List<String>> params, final String key, final boolean mandatory)
		throws ParseException {
		
		String tokenString = MultivaluedMapUtils.getFirstValue(params, key);
		
		if (StringUtils.isBlank(tokenString)) {
			
			if (mandatory) {
				String msg = String.format("Missing or empty %s parameter", key);
				throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
			} else {
				return null;
			}
		}
		
		return new TypelessToken(tokenString);
	}
	
	
	/**
	 * Parses a token exchange grant from the specified request body
	 * parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=urn:ietf:params:oauth:grant-type:token-exchange
	 * resource=https://backend.example.com/api
	 * subject_token=accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC
	 * subject_token_type=urn:ietf:params:oauth:token-type:access_token
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The token exchange grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TokenExchangeGrant parse(final Map<String, List<String>> params)
		throws ParseException {
		
		GrantType.ensure(GRANT_TYPE, params);
		
		List<Audience> audience = parseAudience(params);
		TokenTypeURI requestedTokenType = parseTokenType(params, "requested_token_type", false);
		TypelessToken subjectToken = parseToken(params, "subject_token", true);
		TokenTypeURI subjectTokenType = parseTokenType(params, "subject_token_type", true);
		TypelessToken actorToken = parseToken(params, "actor_token", false);
		TokenTypeURI actorTokenType = parseTokenType(params, "actor_token_type", false);
		
		return new TokenExchangeGrant(subjectToken, subjectTokenType, actorToken, actorTokenType, requestedTokenType, audience);
	}
	
	
	@Override
	public boolean equals(final Object o) {
		
		if (this == o) return true;
		
		if (!(o instanceof TokenExchangeGrant)) return false;
		
		TokenExchangeGrant that = (TokenExchangeGrant) o;
		
		return
			getSubjectToken().equals(that.getSubjectToken()) &&
			getSubjectTokenType().equals(that.getSubjectTokenType()) &&
			
			Objects.equals(getActorToken(), that.getActorToken()) &&
			Objects.equals(getActorTokenType(), that.getActorTokenType()) &&
			Objects.equals(getRequestedTokenType(), that.getRequestedTokenType()) &&
			Objects.equals(getAudience(), that.getAudience());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(
			getSubjectToken(),
			getSubjectTokenType(),
			getActorToken(),
			getActorTokenType(),
			getRequestedTokenType(),
			getAudience()
		);
	}
}

package com.nimbusds.openid.connect.messages;


import com.nimbusds.openid.connect.ParseException;


/**
 * Enumeration the types of display for authentication and consent UIs.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-22)
 */
public enum Display {


	/**
	 * Full user-agent page view (default).
	 */
	PAGE,
	
	
	/**
	 * Popup user-agent window.
	 */
	POPUP,
	
	
	/**
	 * Device that leverages a touch interface. The authorisation server may
	 * attempt to detect the touch device and further customise the 
	 * interface.
	 */
	TOUCH,
	
	
	/**
	 * Feature phone.
	 */
	WAP;


	/**
	 * Gets the default display type ({@link #PAGE}).
	 *
	 * @return The default display type.
	 */
	public static Display getDefault() {
	
		return PAGE;
	}
	
	
	/**
	 * Returns the canonical string representation of this display type.
	 * This is produced by converting the constant to lower case.
	 *
	 * @return The string representation of this display type. 
	 */
	public String toString() {
	
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Parses a display type.
	 *
	 * @param s The string to parse. If the string is {@code null} or empty
	 *          the {@code #getDefault} display type will be returned.
	 *
	 * @return The parsed display type.
	 *
	 * @throws ParseException If the parsed string doesn't match a display 
	 *                        type.
	 */
	public static Display parse(final String s)
		throws ParseException {
	
		if (s == null || s.trim().isEmpty())
			return getDefault();
		
		if (s.equals("page"))
			return PAGE;
			
		else if (s.equals("popup"))
			return POPUP;
			
		else if (s.equals("touch"))
			return TOUCH;
			
		else if (s.equals("wap"))
			return WAP;
			
		else
			throw new ParseException("Couldn't parse display type: Unexpected display type: " + s);
	}
}

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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * ISO 3166-1 alpha-3 (three-letter) country code.
 *
 * <p>Includes constants for all 249 current officially assigned ISO 3166-1
 * alpha-3 codes.
 */
@Immutable
public final class ISO3166_1Alpha3CountryCode extends ISO3166_1AlphaCountryCode {
	
	
	private static final long serialVersionUID = -7659886425656766569L;
	
	
	/** Aruba */
	public static final ISO3166_1Alpha3CountryCode ABW = new ISO3166_1Alpha3CountryCode("ABW");
	
	/** Afghanistan */
	public static final ISO3166_1Alpha3CountryCode AFG = new ISO3166_1Alpha3CountryCode("AFG");
	
	/** Angola */
	public static final ISO3166_1Alpha3CountryCode AGO = new ISO3166_1Alpha3CountryCode("AGO");
	
	/** Anguilla */
	public static final ISO3166_1Alpha3CountryCode AIA = new ISO3166_1Alpha3CountryCode("AIA");
	
	/** Åland Islands */
	public static final ISO3166_1Alpha3CountryCode ALA = new ISO3166_1Alpha3CountryCode("ALA");
	
	/** Albania */
	public static final ISO3166_1Alpha3CountryCode ALB = new ISO3166_1Alpha3CountryCode("ALB");
	
	/** Andorra */
	public static final ISO3166_1Alpha3CountryCode AND = new ISO3166_1Alpha3CountryCode("AND");
	
	/** United Arab Emirates */
	public static final ISO3166_1Alpha3CountryCode ARE = new ISO3166_1Alpha3CountryCode("ARE");
	
	/** Argentina */
	public static final ISO3166_1Alpha3CountryCode ARG = new ISO3166_1Alpha3CountryCode("ARG");
	
	/** Armenia */
	public static final ISO3166_1Alpha3CountryCode ARM = new ISO3166_1Alpha3CountryCode("ARM");
	
	/** American Samoa */
	public static final ISO3166_1Alpha3CountryCode ASM = new ISO3166_1Alpha3CountryCode("ASM");
	
	/** Antarctica */
	public static final ISO3166_1Alpha3CountryCode ATA = new ISO3166_1Alpha3CountryCode("ATA");
	
	/** French Southern Territories */
	public static final ISO3166_1Alpha3CountryCode ATF = new ISO3166_1Alpha3CountryCode("ATF");
	
	/** Antigua and Barbuda */
	public static final ISO3166_1Alpha3CountryCode ATG = new ISO3166_1Alpha3CountryCode("ATG");
	
	/** Australia */
	public static final ISO3166_1Alpha3CountryCode AUS = new ISO3166_1Alpha3CountryCode("AUS");
	
	/** Austria */
	public static final ISO3166_1Alpha3CountryCode AUT = new ISO3166_1Alpha3CountryCode("AUT");
	
	/** Azerbaijan */
	public static final ISO3166_1Alpha3CountryCode AZE = new ISO3166_1Alpha3CountryCode("AZE");
	
	/** Burundi */
	public static final ISO3166_1Alpha3CountryCode BDI = new ISO3166_1Alpha3CountryCode("BDI");
	
	/** Belgium */
	public static final ISO3166_1Alpha3CountryCode BEL = new ISO3166_1Alpha3CountryCode("BEL");
	
	/** Benin */
	public static final ISO3166_1Alpha3CountryCode BEN = new ISO3166_1Alpha3CountryCode("BEN");
	
	/** Bonaire, Sint Eustatius and Saba */
	public static final ISO3166_1Alpha3CountryCode BES = new ISO3166_1Alpha3CountryCode("BES");
	
	/** Burkina Faso */
	public static final ISO3166_1Alpha3CountryCode BFA = new ISO3166_1Alpha3CountryCode("BFA");
	
	/** Bangladesh */
	public static final ISO3166_1Alpha3CountryCode BGD = new ISO3166_1Alpha3CountryCode("BGD");
	
	/** Bulgaria */
	public static final ISO3166_1Alpha3CountryCode BGR = new ISO3166_1Alpha3CountryCode("BGR");
	
	/** Bahrain */
	public static final ISO3166_1Alpha3CountryCode BHR = new ISO3166_1Alpha3CountryCode("BHR");
	
	/** Bahamas */
	public static final ISO3166_1Alpha3CountryCode BHS = new ISO3166_1Alpha3CountryCode("BHS");
	
	/** Bosnia and Herzegovina */
	public static final ISO3166_1Alpha3CountryCode BIH = new ISO3166_1Alpha3CountryCode("BIH");
	
	/** Saint Barthélemy */
	public static final ISO3166_1Alpha3CountryCode BLM = new ISO3166_1Alpha3CountryCode("BLM");
	
	/** Belarus */
	public static final ISO3166_1Alpha3CountryCode BLR = new ISO3166_1Alpha3CountryCode("BLR");
	
	/** Belize */
	public static final ISO3166_1Alpha3CountryCode BLZ = new ISO3166_1Alpha3CountryCode("BLZ");
	
	/** Bermuda */
	public static final ISO3166_1Alpha3CountryCode BMU = new ISO3166_1Alpha3CountryCode("BMU");
	
	/** Bolivia (Plurinational State of) */
	public static final ISO3166_1Alpha3CountryCode BOL = new ISO3166_1Alpha3CountryCode("BOL");
	
	/** Brazil */
	public static final ISO3166_1Alpha3CountryCode BRA = new ISO3166_1Alpha3CountryCode("BRA");
	
	/** Barbados */
	public static final ISO3166_1Alpha3CountryCode BRB = new ISO3166_1Alpha3CountryCode("BRB");
	
	/** Brunei Darussalam */
	public static final ISO3166_1Alpha3CountryCode BRN = new ISO3166_1Alpha3CountryCode("BRN");
	
	/** Bhutan */
	public static final ISO3166_1Alpha3CountryCode BTN = new ISO3166_1Alpha3CountryCode("BTN");
	
	/** Bouvet Island */
	public static final ISO3166_1Alpha3CountryCode BVT = new ISO3166_1Alpha3CountryCode("BVT");
	
	/** Botswana */
	public static final ISO3166_1Alpha3CountryCode BWA = new ISO3166_1Alpha3CountryCode("BWA");
	
	/** Central African Republic */
	public static final ISO3166_1Alpha3CountryCode CAF = new ISO3166_1Alpha3CountryCode("CAF");
	
	/** Canada */
	public static final ISO3166_1Alpha3CountryCode CAN = new ISO3166_1Alpha3CountryCode("CAN");
	
	/** Cocos (Keeling) Islands */
	public static final ISO3166_1Alpha3CountryCode CCK = new ISO3166_1Alpha3CountryCode("CCK");
	
	/** Switzerland */
	public static final ISO3166_1Alpha3CountryCode CHE = new ISO3166_1Alpha3CountryCode("CHE");
	
	/** Chile */
	public static final ISO3166_1Alpha3CountryCode CHL = new ISO3166_1Alpha3CountryCode("CHL");
	
	/** China */
	public static final ISO3166_1Alpha3CountryCode CHN = new ISO3166_1Alpha3CountryCode("CHN");
	
	/** Côte d'Ivoire */
	public static final ISO3166_1Alpha3CountryCode CIV = new ISO3166_1Alpha3CountryCode("CIV");
	
	/** Cameroon */
	public static final ISO3166_1Alpha3CountryCode CMR = new ISO3166_1Alpha3CountryCode("CMR");
	
	/** Congo, Democratic Republic of the */
	public static final ISO3166_1Alpha3CountryCode COD = new ISO3166_1Alpha3CountryCode("COD");
	
	/** Congo */
	public static final ISO3166_1Alpha3CountryCode COG = new ISO3166_1Alpha3CountryCode("COG");
	
	/** Cook Islands */
	public static final ISO3166_1Alpha3CountryCode COK = new ISO3166_1Alpha3CountryCode("COK");
	
	/** Colombia */
	public static final ISO3166_1Alpha3CountryCode COL = new ISO3166_1Alpha3CountryCode("COL");
	
	/** Comoros */
	public static final ISO3166_1Alpha3CountryCode COM = new ISO3166_1Alpha3CountryCode("COM");
	
	/** Cabo Verde */
	public static final ISO3166_1Alpha3CountryCode CPV = new ISO3166_1Alpha3CountryCode("CPV");
	
	/** Costa Rica */
	public static final ISO3166_1Alpha3CountryCode CRI = new ISO3166_1Alpha3CountryCode("CRI");
	
	/** Cuba */
	public static final ISO3166_1Alpha3CountryCode CUB = new ISO3166_1Alpha3CountryCode("CUB");
	
	/** Curaçao */
	public static final ISO3166_1Alpha3CountryCode CUW = new ISO3166_1Alpha3CountryCode("CUW");
	
	/** Christmas Island */
	public static final ISO3166_1Alpha3CountryCode CXR = new ISO3166_1Alpha3CountryCode("CXR");
	
	/** Cayman Islands */
	public static final ISO3166_1Alpha3CountryCode CYM = new ISO3166_1Alpha3CountryCode("CYM");
	
	/** Cyprus */
	public static final ISO3166_1Alpha3CountryCode CYP = new ISO3166_1Alpha3CountryCode("CYP");
	
	/** Czechia */
	public static final ISO3166_1Alpha3CountryCode CZE = new ISO3166_1Alpha3CountryCode("CZE");
	
	/** Germany */
	public static final ISO3166_1Alpha3CountryCode DEU = new ISO3166_1Alpha3CountryCode("DEU");
	
	/** Djibouti */
	public static final ISO3166_1Alpha3CountryCode DJI = new ISO3166_1Alpha3CountryCode("DJI");
	
	/** Dominica */
	public static final ISO3166_1Alpha3CountryCode DMA = new ISO3166_1Alpha3CountryCode("DMA");
	
	/** Denmark */
	public static final ISO3166_1Alpha3CountryCode DNK = new ISO3166_1Alpha3CountryCode("DNK");
	
	/** Dominican Republic */
	public static final ISO3166_1Alpha3CountryCode DOM = new ISO3166_1Alpha3CountryCode("DOM");
	
	/** Algeria */
	public static final ISO3166_1Alpha3CountryCode DZA = new ISO3166_1Alpha3CountryCode("DZA");
	
	/** Ecuador */
	public static final ISO3166_1Alpha3CountryCode ECU = new ISO3166_1Alpha3CountryCode("ECU");
	
	/** Egypt */
	public static final ISO3166_1Alpha3CountryCode EGY = new ISO3166_1Alpha3CountryCode("EGY");
	
	/** Eritrea */
	public static final ISO3166_1Alpha3CountryCode ERI = new ISO3166_1Alpha3CountryCode("ERI");
	
	/** Western Sahara */
	public static final ISO3166_1Alpha3CountryCode ESH = new ISO3166_1Alpha3CountryCode("ESH");
	
	/** Spain */
	public static final ISO3166_1Alpha3CountryCode ESP = new ISO3166_1Alpha3CountryCode("ESP");
	
	/** Estonia */
	public static final ISO3166_1Alpha3CountryCode EST = new ISO3166_1Alpha3CountryCode("EST");
	
	/** Ethiopia */
	public static final ISO3166_1Alpha3CountryCode ETH = new ISO3166_1Alpha3CountryCode("ETH");
	
	/** Finland */
	public static final ISO3166_1Alpha3CountryCode FIN = new ISO3166_1Alpha3CountryCode("FIN");
	
	/** Fiji */
	public static final ISO3166_1Alpha3CountryCode FJI = new ISO3166_1Alpha3CountryCode("FJI");
	
	/** Falkland Islands (Malvinas) */
	public static final ISO3166_1Alpha3CountryCode FLK = new ISO3166_1Alpha3CountryCode("FLK");
	
	/** France */
	public static final ISO3166_1Alpha3CountryCode FRA = new ISO3166_1Alpha3CountryCode("FRA");
	
	/** Faroe Islands */
	public static final ISO3166_1Alpha3CountryCode FRO = new ISO3166_1Alpha3CountryCode("FRO");
	
	/** Micronesia (Federated States of) */
	public static final ISO3166_1Alpha3CountryCode FSM = new ISO3166_1Alpha3CountryCode("FSM");
	
	/** Gabon */
	public static final ISO3166_1Alpha3CountryCode GAB = new ISO3166_1Alpha3CountryCode("GAB");
	
	/** United Kingdom of Great Britain and Northern Ireland */
	public static final ISO3166_1Alpha3CountryCode GBR = new ISO3166_1Alpha3CountryCode("GBR");
	
	/** Georgia */
	public static final ISO3166_1Alpha3CountryCode GEO = new ISO3166_1Alpha3CountryCode("GEO");
	
	/** Guernsey */
	public static final ISO3166_1Alpha3CountryCode GGY = new ISO3166_1Alpha3CountryCode("GGY");
	
	/** Ghana */
	public static final ISO3166_1Alpha3CountryCode GHA = new ISO3166_1Alpha3CountryCode("GHA");
	
	/** Gibraltar */
	public static final ISO3166_1Alpha3CountryCode GIB = new ISO3166_1Alpha3CountryCode("GIB");
	
	/** Guinea */
	public static final ISO3166_1Alpha3CountryCode GIN = new ISO3166_1Alpha3CountryCode("GIN");
	
	/** Guadeloupe */
	public static final ISO3166_1Alpha3CountryCode GLP = new ISO3166_1Alpha3CountryCode("GLP");
	
	/** Gambia */
	public static final ISO3166_1Alpha3CountryCode GMB = new ISO3166_1Alpha3CountryCode("GMB");
	
	/** Guinea-Bissau */
	public static final ISO3166_1Alpha3CountryCode GNB = new ISO3166_1Alpha3CountryCode("GNB");
	
	/** Equatorial Guinea */
	public static final ISO3166_1Alpha3CountryCode GNQ = new ISO3166_1Alpha3CountryCode("GNQ");
	
	/** Greece */
	public static final ISO3166_1Alpha3CountryCode GRC = new ISO3166_1Alpha3CountryCode("GRC");
	
	/** Grenada */
	public static final ISO3166_1Alpha3CountryCode GRD = new ISO3166_1Alpha3CountryCode("GRD");
	
	/** Greenland */
	public static final ISO3166_1Alpha3CountryCode GRL = new ISO3166_1Alpha3CountryCode("GRL");
	
	/** Guatemala */
	public static final ISO3166_1Alpha3CountryCode GTM = new ISO3166_1Alpha3CountryCode("GTM");
	
	/** French Guiana */
	public static final ISO3166_1Alpha3CountryCode GUF = new ISO3166_1Alpha3CountryCode("GUF");
	
	/** Guam */
	public static final ISO3166_1Alpha3CountryCode GUM = new ISO3166_1Alpha3CountryCode("GUM");
	
	/** Guyana */
	public static final ISO3166_1Alpha3CountryCode GUY = new ISO3166_1Alpha3CountryCode("GUY");
	
	/** Hong Kong */
	public static final ISO3166_1Alpha3CountryCode HKG = new ISO3166_1Alpha3CountryCode("HKG");
	
	/** Heard Island and McDonald Islands */
	public static final ISO3166_1Alpha3CountryCode HMD = new ISO3166_1Alpha3CountryCode("HMD");
	
	/** Honduras */
	public static final ISO3166_1Alpha3CountryCode HND = new ISO3166_1Alpha3CountryCode("HND");
	
	/** Croatia */
	public static final ISO3166_1Alpha3CountryCode HRV = new ISO3166_1Alpha3CountryCode("HRV");
	
	/** Haiti */
	public static final ISO3166_1Alpha3CountryCode HTI = new ISO3166_1Alpha3CountryCode("HTI");
	
	/** Hungary */
	public static final ISO3166_1Alpha3CountryCode HUN = new ISO3166_1Alpha3CountryCode("HUN");
	
	/** Indonesia */
	public static final ISO3166_1Alpha3CountryCode IDN = new ISO3166_1Alpha3CountryCode("IDN");
	
	/** Isle of Man */
	public static final ISO3166_1Alpha3CountryCode IMN = new ISO3166_1Alpha3CountryCode("IMN");
	
	/** India */
	public static final ISO3166_1Alpha3CountryCode IND = new ISO3166_1Alpha3CountryCode("IND");
	
	/** British Indian Ocean Territory */
	public static final ISO3166_1Alpha3CountryCode IOT = new ISO3166_1Alpha3CountryCode("IOT");
	
	/** Ireland */
	public static final ISO3166_1Alpha3CountryCode IRL = new ISO3166_1Alpha3CountryCode("IRL");
	
	/** Iran (Islamic Republic of) */
	public static final ISO3166_1Alpha3CountryCode IRN = new ISO3166_1Alpha3CountryCode("IRN");
	
	/** Iraq */
	public static final ISO3166_1Alpha3CountryCode IRQ = new ISO3166_1Alpha3CountryCode("IRQ");
	
	/** Iceland */
	public static final ISO3166_1Alpha3CountryCode ISL = new ISO3166_1Alpha3CountryCode("ISL");
	
	/** Israel */
	public static final ISO3166_1Alpha3CountryCode ISR = new ISO3166_1Alpha3CountryCode("ISR");
	
	/** Italy */
	public static final ISO3166_1Alpha3CountryCode ITA = new ISO3166_1Alpha3CountryCode("ITA");
	
	/** Jamaica */
	public static final ISO3166_1Alpha3CountryCode JAM = new ISO3166_1Alpha3CountryCode("JAM");
	
	/** Jersey */
	public static final ISO3166_1Alpha3CountryCode JEY = new ISO3166_1Alpha3CountryCode("JEY");
	
	/** Jordan */
	public static final ISO3166_1Alpha3CountryCode JOR = new ISO3166_1Alpha3CountryCode("JOR");
	
	/** Japan */
	public static final ISO3166_1Alpha3CountryCode JPN = new ISO3166_1Alpha3CountryCode("JPN");
	
	/** Kazakhstan */
	public static final ISO3166_1Alpha3CountryCode KAZ = new ISO3166_1Alpha3CountryCode("KAZ");
	
	/** Kenya */
	public static final ISO3166_1Alpha3CountryCode KEN = new ISO3166_1Alpha3CountryCode("KEN");
	
	/** Kyrgyzstan */
	public static final ISO3166_1Alpha3CountryCode KGZ = new ISO3166_1Alpha3CountryCode("KGZ");
	
	/** Cambodia */
	public static final ISO3166_1Alpha3CountryCode KHM = new ISO3166_1Alpha3CountryCode("KHM");
	
	/** Kiribati */
	public static final ISO3166_1Alpha3CountryCode KIR = new ISO3166_1Alpha3CountryCode("KIR");
	
	/** Saint Kitts and Nevis */
	public static final ISO3166_1Alpha3CountryCode KNA = new ISO3166_1Alpha3CountryCode("KNA");
	
	/** Korea, Republic of */
	public static final ISO3166_1Alpha3CountryCode KOR = new ISO3166_1Alpha3CountryCode("KOR");
	
	/** Kuwait */
	public static final ISO3166_1Alpha3CountryCode KWT = new ISO3166_1Alpha3CountryCode("KWT");
	
	/** Lao People's Democratic Republic */
	public static final ISO3166_1Alpha3CountryCode LAO = new ISO3166_1Alpha3CountryCode("LAO");
	
	/** Lebanon */
	public static final ISO3166_1Alpha3CountryCode LBN = new ISO3166_1Alpha3CountryCode("LBN");
	
	/** Liberia */
	public static final ISO3166_1Alpha3CountryCode LBR = new ISO3166_1Alpha3CountryCode("LBR");
	
	/** Libya */
	public static final ISO3166_1Alpha3CountryCode LBY = new ISO3166_1Alpha3CountryCode("LBY");
	
	/** Saint Lucia */
	public static final ISO3166_1Alpha3CountryCode LCA = new ISO3166_1Alpha3CountryCode("LCA");
	
	/** Liechtenstein */
	public static final ISO3166_1Alpha3CountryCode LIE = new ISO3166_1Alpha3CountryCode("LIE");
	
	/** Sri Lanka */
	public static final ISO3166_1Alpha3CountryCode LKA = new ISO3166_1Alpha3CountryCode("LKA");
	
	/** Lesotho */
	public static final ISO3166_1Alpha3CountryCode LSO = new ISO3166_1Alpha3CountryCode("LSO");
	
	/** Lithuania */
	public static final ISO3166_1Alpha3CountryCode LTU = new ISO3166_1Alpha3CountryCode("LTU");
	
	/** Luxembourg */
	public static final ISO3166_1Alpha3CountryCode LUX = new ISO3166_1Alpha3CountryCode("LUX");
	
	/** Latvia */
	public static final ISO3166_1Alpha3CountryCode LVA = new ISO3166_1Alpha3CountryCode("LVA");
	
	/** Macao */
	public static final ISO3166_1Alpha3CountryCode MAC = new ISO3166_1Alpha3CountryCode("MAC");
	
	/** Saint Martin (French part) */
	public static final ISO3166_1Alpha3CountryCode MAF = new ISO3166_1Alpha3CountryCode("MAF");
	
	/** Morocco */
	public static final ISO3166_1Alpha3CountryCode MAR = new ISO3166_1Alpha3CountryCode("MAR");
	
	/** Monaco */
	public static final ISO3166_1Alpha3CountryCode MCO = new ISO3166_1Alpha3CountryCode("MCO");
	
	/** Moldova, Republic of */
	public static final ISO3166_1Alpha3CountryCode MDA = new ISO3166_1Alpha3CountryCode("MDA");
	
	/** Madagascar */
	public static final ISO3166_1Alpha3CountryCode MDG = new ISO3166_1Alpha3CountryCode("MDG");
	
	/** Maldives */
	public static final ISO3166_1Alpha3CountryCode MDV = new ISO3166_1Alpha3CountryCode("MDV");
	
	/** Mexico */
	public static final ISO3166_1Alpha3CountryCode MEX = new ISO3166_1Alpha3CountryCode("MEX");
	
	/** Marshall Islands */
	public static final ISO3166_1Alpha3CountryCode MHL = new ISO3166_1Alpha3CountryCode("MHL");
	
	/** North Macedonia */
	public static final ISO3166_1Alpha3CountryCode MKD = new ISO3166_1Alpha3CountryCode("MKD");
	
	/** Mali */
	public static final ISO3166_1Alpha3CountryCode MLI = new ISO3166_1Alpha3CountryCode("MLI");
	
	/** Malta */
	public static final ISO3166_1Alpha3CountryCode MLT = new ISO3166_1Alpha3CountryCode("MLT");
	
	/** Myanmar */
	public static final ISO3166_1Alpha3CountryCode MMR = new ISO3166_1Alpha3CountryCode("MMR");
	
	/** Montenegro */
	public static final ISO3166_1Alpha3CountryCode MNE = new ISO3166_1Alpha3CountryCode("MNE");
	
	/** Mongolia */
	public static final ISO3166_1Alpha3CountryCode MNG = new ISO3166_1Alpha3CountryCode("MNG");
	
	/** Northern Mariana Islands */
	public static final ISO3166_1Alpha3CountryCode MNP = new ISO3166_1Alpha3CountryCode("MNP");
	
	/** Mozambique */
	public static final ISO3166_1Alpha3CountryCode MOZ = new ISO3166_1Alpha3CountryCode("MOZ");
	
	/** Mauritania */
	public static final ISO3166_1Alpha3CountryCode MRT = new ISO3166_1Alpha3CountryCode("MRT");
	
	/** Montserrat */
	public static final ISO3166_1Alpha3CountryCode MSR = new ISO3166_1Alpha3CountryCode("MSR");
	
	/** Martinique */
	public static final ISO3166_1Alpha3CountryCode MTQ = new ISO3166_1Alpha3CountryCode("MTQ");
	
	/** Mauritius */
	public static final ISO3166_1Alpha3CountryCode MUS = new ISO3166_1Alpha3CountryCode("MUS");
	
	/** Malawi */
	public static final ISO3166_1Alpha3CountryCode MWI = new ISO3166_1Alpha3CountryCode("MWI");
	
	/** Malaysia */
	public static final ISO3166_1Alpha3CountryCode MYS = new ISO3166_1Alpha3CountryCode("MYS");
	
	/** Mayotte */
	public static final ISO3166_1Alpha3CountryCode MYT = new ISO3166_1Alpha3CountryCode("MYT");
	
	/** Namibia */
	public static final ISO3166_1Alpha3CountryCode NAM = new ISO3166_1Alpha3CountryCode("NAM");
	
	/** New Caledonia */
	public static final ISO3166_1Alpha3CountryCode NCL = new ISO3166_1Alpha3CountryCode("NCL");
	
	/** Niger */
	public static final ISO3166_1Alpha3CountryCode NER = new ISO3166_1Alpha3CountryCode("NER");
	
	/** Norfolk Island */
	public static final ISO3166_1Alpha3CountryCode NFK = new ISO3166_1Alpha3CountryCode("NFK");
	
	/** Nigeria */
	public static final ISO3166_1Alpha3CountryCode NGA = new ISO3166_1Alpha3CountryCode("NGA");
	
	/** Nicaragua */
	public static final ISO3166_1Alpha3CountryCode NIC = new ISO3166_1Alpha3CountryCode("NIC");
	
	/** Niue */
	public static final ISO3166_1Alpha3CountryCode NIU = new ISO3166_1Alpha3CountryCode("NIU");
	
	/** Netherlands */
	public static final ISO3166_1Alpha3CountryCode NLD = new ISO3166_1Alpha3CountryCode("NLD");
	
	/** Norway */
	public static final ISO3166_1Alpha3CountryCode NOR = new ISO3166_1Alpha3CountryCode("NOR");
	
	/** Nepal */
	public static final ISO3166_1Alpha3CountryCode NPL = new ISO3166_1Alpha3CountryCode("NPL");
	
	/** Nauru */
	public static final ISO3166_1Alpha3CountryCode NRU = new ISO3166_1Alpha3CountryCode("NRU");
	
	/** New Zealand */
	public static final ISO3166_1Alpha3CountryCode NZL = new ISO3166_1Alpha3CountryCode("NZL");
	
	/** Oman */
	public static final ISO3166_1Alpha3CountryCode OMN = new ISO3166_1Alpha3CountryCode("OMN");
	
	/** Pakistan */
	public static final ISO3166_1Alpha3CountryCode PAK = new ISO3166_1Alpha3CountryCode("PAK");
	
	/** Panama */
	public static final ISO3166_1Alpha3CountryCode PAN = new ISO3166_1Alpha3CountryCode("PAN");
	
	/** Pitcairn */
	public static final ISO3166_1Alpha3CountryCode PCN = new ISO3166_1Alpha3CountryCode("PCN");
	
	/** Peru */
	public static final ISO3166_1Alpha3CountryCode PER = new ISO3166_1Alpha3CountryCode("PER");
	
	/** Philippines */
	public static final ISO3166_1Alpha3CountryCode PHL = new ISO3166_1Alpha3CountryCode("PHL");
	
	/** Palau */
	public static final ISO3166_1Alpha3CountryCode PLW = new ISO3166_1Alpha3CountryCode("PLW");
	
	/** Papua New Guinea */
	public static final ISO3166_1Alpha3CountryCode PNG = new ISO3166_1Alpha3CountryCode("PNG");
	
	/** Poland */
	public static final ISO3166_1Alpha3CountryCode POL = new ISO3166_1Alpha3CountryCode("POL");
	
	/** Puerto Rico */
	public static final ISO3166_1Alpha3CountryCode PRI = new ISO3166_1Alpha3CountryCode("PRI");
	
	/** Korea (Democratic People's Republic of) */
	public static final ISO3166_1Alpha3CountryCode PRK = new ISO3166_1Alpha3CountryCode("PRK");
	
	/** Portugal */
	public static final ISO3166_1Alpha3CountryCode PRT = new ISO3166_1Alpha3CountryCode("PRT");
	
	/** Paraguay */
	public static final ISO3166_1Alpha3CountryCode PRY = new ISO3166_1Alpha3CountryCode("PRY");
	
	/** Palestine, State of */
	public static final ISO3166_1Alpha3CountryCode PSE = new ISO3166_1Alpha3CountryCode("PSE");
	
	/** French Polynesia */
	public static final ISO3166_1Alpha3CountryCode PYF = new ISO3166_1Alpha3CountryCode("PYF");
	
	/** Qatar */
	public static final ISO3166_1Alpha3CountryCode QAT = new ISO3166_1Alpha3CountryCode("QAT");
	
	/** Réunion */
	public static final ISO3166_1Alpha3CountryCode REU = new ISO3166_1Alpha3CountryCode("REU");
	
	/** Romania */
	public static final ISO3166_1Alpha3CountryCode ROU = new ISO3166_1Alpha3CountryCode("ROU");
	
	/** Russian Federation */
	public static final ISO3166_1Alpha3CountryCode RUS = new ISO3166_1Alpha3CountryCode("RUS");
	
	/** Rwanda */
	public static final ISO3166_1Alpha3CountryCode RWA = new ISO3166_1Alpha3CountryCode("RWA");
	
	/** Saudi Arabia */
	public static final ISO3166_1Alpha3CountryCode SAU = new ISO3166_1Alpha3CountryCode("SAU");
	
	/** Sudan */
	public static final ISO3166_1Alpha3CountryCode SDN = new ISO3166_1Alpha3CountryCode("SDN");
	
	/** Senegal */
	public static final ISO3166_1Alpha3CountryCode SEN = new ISO3166_1Alpha3CountryCode("SEN");
	
	/** Singapore */
	public static final ISO3166_1Alpha3CountryCode SGP = new ISO3166_1Alpha3CountryCode("SGP");
	
	/** South Georgia and the South Sandwich Islands */
	public static final ISO3166_1Alpha3CountryCode SGS = new ISO3166_1Alpha3CountryCode("SGS");
	
	/** Saint Helena, Ascension and Tristan da Cunha */
	public static final ISO3166_1Alpha3CountryCode SHN = new ISO3166_1Alpha3CountryCode("SHN");
	
	/** Svalbard and Jan Mayen */
	public static final ISO3166_1Alpha3CountryCode SJM = new ISO3166_1Alpha3CountryCode("SJM");
	
	/** Solomon Islands */
	public static final ISO3166_1Alpha3CountryCode SLB = new ISO3166_1Alpha3CountryCode("SLB");
	
	/** Sierra Leone */
	public static final ISO3166_1Alpha3CountryCode SLE = new ISO3166_1Alpha3CountryCode("SLE");
	
	/** El Salvador */
	public static final ISO3166_1Alpha3CountryCode SLV = new ISO3166_1Alpha3CountryCode("SLV");
	
	/** San Marino */
	public static final ISO3166_1Alpha3CountryCode SMR = new ISO3166_1Alpha3CountryCode("SMR");
	
	/** Somalia */
	public static final ISO3166_1Alpha3CountryCode SOM = new ISO3166_1Alpha3CountryCode("SOM");
	
	/** Saint Pierre and Miquelon */
	public static final ISO3166_1Alpha3CountryCode SPM = new ISO3166_1Alpha3CountryCode("SPM");
	
	/** Serbia */
	public static final ISO3166_1Alpha3CountryCode SRB = new ISO3166_1Alpha3CountryCode("SRB");
	
	/** South Sudan */
	public static final ISO3166_1Alpha3CountryCode SSD = new ISO3166_1Alpha3CountryCode("SSD");
	
	/** Sao Tome and Principe */
	public static final ISO3166_1Alpha3CountryCode STP = new ISO3166_1Alpha3CountryCode("STP");
	
	/** Suriname */
	public static final ISO3166_1Alpha3CountryCode SUR = new ISO3166_1Alpha3CountryCode("SUR");
	
	/** Slovakia */
	public static final ISO3166_1Alpha3CountryCode SVK = new ISO3166_1Alpha3CountryCode("SVK");
	
	/** Slovenia */
	public static final ISO3166_1Alpha3CountryCode SVN = new ISO3166_1Alpha3CountryCode("SVN");
	
	/** Sweden */
	public static final ISO3166_1Alpha3CountryCode SWE = new ISO3166_1Alpha3CountryCode("SWE");
	
	/** Eswatini */
	public static final ISO3166_1Alpha3CountryCode SWZ = new ISO3166_1Alpha3CountryCode("SWZ");
	
	/** Sint Maarten (Dutch part) */
	public static final ISO3166_1Alpha3CountryCode SXM = new ISO3166_1Alpha3CountryCode("SXM");
	
	/** Seychelles */
	public static final ISO3166_1Alpha3CountryCode SYC = new ISO3166_1Alpha3CountryCode("SYC");
	
	/** Syrian Arab Republic */
	public static final ISO3166_1Alpha3CountryCode SYR = new ISO3166_1Alpha3CountryCode("SYR");
	
	/** Turks and Caicos Islands */
	public static final ISO3166_1Alpha3CountryCode TCA = new ISO3166_1Alpha3CountryCode("TCA");
	
	/** Chad */
	public static final ISO3166_1Alpha3CountryCode TCD = new ISO3166_1Alpha3CountryCode("TCD");
	
	/** Togo */
	public static final ISO3166_1Alpha3CountryCode TGO = new ISO3166_1Alpha3CountryCode("TGO");
	
	/** Thailand */
	public static final ISO3166_1Alpha3CountryCode THA = new ISO3166_1Alpha3CountryCode("THA");
	
	/** Tajikistan */
	public static final ISO3166_1Alpha3CountryCode TJK = new ISO3166_1Alpha3CountryCode("TJK");
	
	/** Tokelau */
	public static final ISO3166_1Alpha3CountryCode TKL = new ISO3166_1Alpha3CountryCode("TKL");
	
	/** Turkmenistan */
	public static final ISO3166_1Alpha3CountryCode TKM = new ISO3166_1Alpha3CountryCode("TKM");
	
	/** Timor-Leste */
	public static final ISO3166_1Alpha3CountryCode TLS = new ISO3166_1Alpha3CountryCode("TLS");
	
	/** Tonga */
	public static final ISO3166_1Alpha3CountryCode TON = new ISO3166_1Alpha3CountryCode("TON");
	
	/** Trinidad and Tobago */
	public static final ISO3166_1Alpha3CountryCode TTO = new ISO3166_1Alpha3CountryCode("TTO");
	
	/** Tunisia */
	public static final ISO3166_1Alpha3CountryCode TUN = new ISO3166_1Alpha3CountryCode("TUN");
	
	/** Turkey */
	public static final ISO3166_1Alpha3CountryCode TUR = new ISO3166_1Alpha3CountryCode("TUR");
	
	/** Tuvalu */
	public static final ISO3166_1Alpha3CountryCode TUV = new ISO3166_1Alpha3CountryCode("TUV");
	
	/** Taiwan, Province of China */
	public static final ISO3166_1Alpha3CountryCode TWN = new ISO3166_1Alpha3CountryCode("TWN");
	
	/** Tanzania, United Republic of */
	public static final ISO3166_1Alpha3CountryCode TZA = new ISO3166_1Alpha3CountryCode("TZA");
	
	/** Uganda */
	public static final ISO3166_1Alpha3CountryCode UGA = new ISO3166_1Alpha3CountryCode("UGA");
	
	/** Ukraine */
	public static final ISO3166_1Alpha3CountryCode UKR = new ISO3166_1Alpha3CountryCode("UKR");
	
	/** United States Minor Outlying Islands */
	public static final ISO3166_1Alpha3CountryCode UMI = new ISO3166_1Alpha3CountryCode("UMI");
	
	/** Uruguay */
	public static final ISO3166_1Alpha3CountryCode URY = new ISO3166_1Alpha3CountryCode("URY");
	
	/** United States of America */
	public static final ISO3166_1Alpha3CountryCode USA = new ISO3166_1Alpha3CountryCode("USA");
	
	/** Uzbekistan */
	public static final ISO3166_1Alpha3CountryCode UZB = new ISO3166_1Alpha3CountryCode("UZB");
	
	/** Holy See */
	public static final ISO3166_1Alpha3CountryCode VAT = new ISO3166_1Alpha3CountryCode("VAT");
	
	/** Saint Vincent and the Grenadines */
	public static final ISO3166_1Alpha3CountryCode VCT = new ISO3166_1Alpha3CountryCode("VCT");
	
	/** Venezuela (Bolivarian Republic of) */
	public static final ISO3166_1Alpha3CountryCode VEN = new ISO3166_1Alpha3CountryCode("VEN");
	
	/** Virgin Islands (British) */
	public static final ISO3166_1Alpha3CountryCode VGB = new ISO3166_1Alpha3CountryCode("VGB");
	
	/** Virgin Islands (U.S.) */
	public static final ISO3166_1Alpha3CountryCode VIR = new ISO3166_1Alpha3CountryCode("VIR");
	
	/** Viet Nam */
	public static final ISO3166_1Alpha3CountryCode VNM = new ISO3166_1Alpha3CountryCode("VNM");
	
	/** Vanuatu */
	public static final ISO3166_1Alpha3CountryCode VUT = new ISO3166_1Alpha3CountryCode("VUT");
	
	/** Wallis and Futuna */
	public static final ISO3166_1Alpha3CountryCode WLF = new ISO3166_1Alpha3CountryCode("WLF");
	
	/** Samoa */
	public static final ISO3166_1Alpha3CountryCode WSM = new ISO3166_1Alpha3CountryCode("WSM");
	
	/** Yemen */
	public static final ISO3166_1Alpha3CountryCode YEM = new ISO3166_1Alpha3CountryCode("YEM");
	
	/** South Africa */
	public static final ISO3166_1Alpha3CountryCode ZAF = new ISO3166_1Alpha3CountryCode("ZAF");
	
	/** Zambia */
	public static final ISO3166_1Alpha3CountryCode ZMB = new ISO3166_1Alpha3CountryCode("ZMB");
	
	/** Zimbabwe */
	public static final ISO3166_1Alpha3CountryCode ZWE = new ISO3166_1Alpha3CountryCode("ZWE");
	
	
	/**
	 * The {@code iso3166_1alpha3-codes.properties} resource.
	 */
	private static final Properties CODES_RESOURCE = new Properties();
	
	
	/**
	 * Creates a new ISO 3166-1 alpha-3 country code. Normalises the code
	 * to upper case.
	 *
	 * @param value The country code value, must be three-letter.
	 */
	public ISO3166_1Alpha3CountryCode(final String value) {
		super(value);
		if (value.length() != 3) {
			throw new IllegalArgumentException("The ISO 3166-1 alpha-3 country code must be 3 letters");
		}
	}
	
	
	/**
	 * Returns the matching alpha-2 country code. See
	 * {@link ISO3166_1AlphaCountryCodeMapper}.
	 *
	 * @return The matching alpha-2 country code, {@code null} if none.
	 */
	public ISO3166_1Alpha2CountryCode toAlpha2CountryCode() {
		
		return ISO3166_1AlphaCountryCodeMapper.toAlpha2CountryCode(this);
	}
	
	
	/**
	 * Returns the country name if available in the
	 * {@code iso3166_1alpha3-codes.properties} resource.
	 *
	 * @return The country name, {@code null} if not available.
	 */
	@Override
	public String getCountryName() {
		
		if (CODES_RESOURCE.isEmpty()) {
			try (InputStream is = getClass().getClassLoader().getResourceAsStream("iso3166_1alpha3-codes.properties")) {
				CODES_RESOURCE.load(is);
			} catch (IOException e) {
				return null;
			}
		}
		
		return CODES_RESOURCE.getProperty(getValue());
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ISO3166_1Alpha3CountryCode &&
			this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an ISO 3166-1 alpha-3 (three-letter) country code.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The ISO 3166-1 alpha-3 (three-letter) country code.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ISO3166_1Alpha3CountryCode parse(final String s)
		throws ParseException {
		
		try {
			return new ISO3166_1Alpha3CountryCode(s);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}

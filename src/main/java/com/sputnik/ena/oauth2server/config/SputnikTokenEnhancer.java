package com.sputnik.ena.oauth2server.config;

import java.util.*;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;


public class SputnikTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken oauth2AccessToken, OAuth2Authentication auth) {
		final Map<String, Object> supplimentaryInfo = new HashMap<>();
		//supplimentaryInfo.put("organization", auth.getName());
		if("admin".equals(auth.getName())) {
			supplimentaryInfo.put("organization", "ena");
		}else if("user".equals(auth.getName())) {
			supplimentaryInfo.put("organization", "dio");
		}		
		((DefaultOAuth2AccessToken) oauth2AccessToken).setAdditionalInformation(supplimentaryInfo);
		return oauth2AccessToken;
	}


}

package com.sputnik.ena.oauth2server.config;



import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;
	
	@Autowired
	UserDetailsService userDetailsService;
	
	@Override
	public void configure(final AuthorizationServerSecurityConfigurer authServerConfig) throws Exception {
		authServerConfig.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}
	
	@Override
	public void configure(final ClientDetailsServiceConfigurer clientConfig) throws Exception {
		clientConfig.inMemory()
			.withClient("sputnikWeb")
			.secret(passwordEncoder().encode("sputnikEn@Web321"))
			.authorizedGrantTypes("password", "authorization_code", "refresh_token")
			.scopes("read", "write")
			.accessTokenValiditySeconds(600)
			.refreshTokenValiditySeconds(3600)
			.and()
			.withClient("sputnikAndroid")
			.secret(passwordEncoder().encode("sputnikEn@Android321"))
			.authorizedGrantTypes("password", "authorization_code", "refresh_token")
			.scopes("read", "write")
			.accessTokenValiditySeconds(600)
			.refreshTokenValiditySeconds(3600);
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), jwtAccessTokenConverter()));
		endpoints.tokenStore(tokenStore())
			.tokenEnhancer(tokenEnhancerChain)
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService);
		
		super.configure(endpoints);
	}
	
	
	@Bean
	@Primary
	public DefaultTokenServices tokenServices() {
		final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore());
		defaultTokenServices.setSupportRefreshToken(true);
		return defaultTokenServices;
	}
	
	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtTokenConverter = new JwtAccessTokenConverter();
		jwtTokenConverter.setSigningKey("sputnik@007");
		return jwtTokenConverter;
	}
	
	@Bean
	public TokenEnhancer tokenEnhancer() {
		return new MyTokenEnhancer();
	}
	
	@Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
}

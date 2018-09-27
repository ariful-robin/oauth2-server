package com.sputnik.ena.oauth2server.config;



import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
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
	
	@Value("${oauth.client1.id}")
	private String client1Id;
	
	@Value("${oauth.client1.secret}")
	private String client1Secret;
	
	@Value("${oauth.client2.id}")
	private String client2Id;
	
	@Value("${oauth.client2.secret}")
	private String client2Secret;
	
	@Value("${oauth.access.token.validity}")
	private int accessTokenValidity;
	
	@Value("${oauth.refresh.token.validity}")
	private int refreshTokenValidity;

	@Value("${oauth.jwt.signing.key}")
	private String signingKey;
	
	
	@Override
	public void configure(final AuthorizationServerSecurityConfigurer authServerConfig) throws Exception {
		authServerConfig.tokenKeyAccess("permitAll()")
						.checkTokenAccess("isAuthenticated()");
						//.checkTokenAccess("permitAll()");
	}
	
	@Override
	public void configure(final ClientDetailsServiceConfigurer clientConfig) throws Exception {
		clientConfig.inMemory()
			.withClient(client1Id)
			.secret(passwordEncoder().encode(client1Secret))
			.authorizedGrantTypes("password", "authorization_code", "refresh_token")
			.scopes("read", "write")
			.accessTokenValiditySeconds(accessTokenValidity)
			.refreshTokenValiditySeconds(refreshTokenValidity)
			.and()
			.withClient(client2Id)
			.secret(passwordEncoder().encode(client2Secret))
			.authorizedGrantTypes("password", "authorization_code", "refresh_token")
			.scopes("read", "write")
			.accessTokenValiditySeconds(accessTokenValidity)
			.refreshTokenValiditySeconds(refreshTokenValidity);
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
		jwtTokenConverter.setSigningKey(signingKey);
		return jwtTokenConverter;
	}
	
	@Bean
	public TokenEnhancer tokenEnhancer() {
		return new SputnikTokenEnhancer();
	}
	
	@Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
}

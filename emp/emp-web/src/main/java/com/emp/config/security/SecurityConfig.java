
package com.emp.config.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.writers.frameoptions.WhiteListedAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

@Configuration
@EnableWebSecurity
@Order(Ordered.LOWEST_PRECEDENCE - 6)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment env;

	@Override
	public void configure(WebSecurity web) throws Exception {

		web.ignoring().antMatchers("/resources/**");
	}

	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable();
		http.headers().addHeaderWriter(new XFrameOptionsHeaderWriter(new WhiteListedAllowFromStrategy(Arrays.asList(env.getProperty("allowed.origins")))));
		/*	http.authorizeRequests()
			//.antMatchers("/", "/login.html", "/app/**", "/assets/**", "/login", "/failure", "/api/v1/*", "/register", "/mlsDropOffService/*", "/searchDetails")
			    .antMatchers("/",
			                 "/login.html",
			                 "/app/**",
			                 "/assets/**",
			                 "/login",
			                 "/failure",
			                 "/api/v1/*",
			                 "/index/solr*",
			                 "/register",
			                 "/test/**",
			                 "/homeunion/**",
			                 "/report/**",
			                 "/index.html/**",
			                 "/index1.html/**",
			                 "/search.html/**",
			                 "/es/search/**",
			                 "/search/**")
			    .permitAll()
			    .anyRequest()
			    .authenticated()
			    .and()
			    .formLogin()
			    .loginPage("/login")
			    .permitAll()
			    .and()
			    .logout()
			    .permitAll();*/
		http.authorizeRequests().anyRequest().permitAll();
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

		auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
	}
}

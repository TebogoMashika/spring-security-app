package com.techlead.userservice.security;


import com.techlead.userservice.security.filter.CustomAuthenticationFilter;
import com.techlead.userservice.security.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // Notes
     //  - AuthenticationManagerBuilder - used to create an AuthenticationManager
    //  users can be authenticated through:
         // 1. in memory authentication,
         // 2. LDAP authentication,
         // 3. JDBC based authentication,
         // 4. UserDetailsService
         // 5. AuthenticationProvider 's.

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // tells spring how to look for users/ authenticate users

        //  UserDetailsService interface is used to retrieve user-related data
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // override the default spring security login
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");


        // disable csrf - Cross-Site Request Forgery = is an attack that forces authenticated users to submit a request to a Web application against which they are currently authenticated
        http.csrf().disable();

        // session will be stateless - meaning the information of the session will not be saved in memory
        // No session will be created or used by Spring Security
        //
        http.sessionManagement().sessionCreationPolicy(STATELESS);

        // allow all request on this endpoint
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();

        // checks who/ what endpoint can access this application
        // the following means: any user who has the role "ROLE_USER" can access this path "api/user/**
        http.authorizeRequests().antMatchers(GET, "api/user/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(POST, "api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().antMatchers(POST, "api/role/adduser/**").hasAnyAuthority("ROLE_ADMIN");

        // every endpoint will be authenticated
        http.authorizeRequests().anyRequest().authenticated();

        // authentication filters - check the users when they try to log in
        // this will call the AuthenticationManager which is called when the application starts
        // AuthenticationManager has a method "authenticate" which will authenticate the user
        http.addFilter(customAuthenticationFilter);

        // added the filter - CustomAuthorizationFilter
        // this filter needs to come before the other filters
        // because we need to intercept any request before the other filters
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    // because the CustomAuthenticationFilter has a contractor that takes  AuthenticationManager
    // we create the Bean in this class which will be executed when the application starts and
    // passed to the authenticationManagerBean when needed
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        // we use super to refer to the parent class
        return super.authenticationManagerBean();
    }
}

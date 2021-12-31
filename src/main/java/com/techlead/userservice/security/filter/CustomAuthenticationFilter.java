package com.techlead.userservice.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // Authenticate the user when trying to log in
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // get params of the request - the request.getParameter for password is not working and throwing a 401 response
        //String username = request.getParameter("username");
        //String password = request.getParameter("password");

        // get header attributes
        String username = request.getHeader("username");
        String password = request.getHeader("password");


        log.info("username is: {}" , username);
        log.info("password is: {}" , password);

        // pass the params into  UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // return token to be authenticated by the authenticationManager
        return authenticationManager.authenticate(authenticationToken);
    }

    // manages successful Authentication
    // method called after successful Authentication
    // we create a token for the user in this method
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {

        // access user that has successfully logged in
        // the principle is the use that has successfully logged in
        User user = (User) authentication.getPrincipal();

        // get user details that is logged in to create a token
        // this will be the algorithm that we will sign and sent to the Json token
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

        // create a token
        // first token when user logs in
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 100 + 100 + 100))
                .withIssuer(request.getRequestURI().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);


        // create a second token
        // refreshed token when user logs in
        String refreshed_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 200 + 200 + 100))
                .withIssuer(request.getRequestURI().toString())
                .sign(algorithm);


        // pass the token to the header
        //response.setHeader("access_token", access_token);
        //response.setHeader("refreshed_token", refreshed_token);

        // this will return the response in a nice JSON format
        Map<String,String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refreshed_token", refreshed_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}

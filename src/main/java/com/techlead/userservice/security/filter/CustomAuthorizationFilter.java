package com.techlead.userservice.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    // the OncePerRequestFilter will intercept every response coming to the application

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // first check if the request coming in is from the login path
        // if its from the login path let it through
        // user is just trying to log in
        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh/")){

            // this will just pass the request  to the next filter in the filter chain
            filterChain.doFilter(request, response);
        }else {

            // get the header of the request
            // AUTHORIZATION - is the key we are looking for in the header
            String authorizationHeader = request.getHeader(AUTHORIZATION);

            // check if the authorizationHeader is not null and starts with "Bearer "
            // when ever we are logged in we will pass the word "Bearer " + token
            // this mean that the user is the bearer of the token ,and we don't need to do more validations
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){

                // use try in case we get an error
                try {
                    // get the token by calling the header and remove the "Bearer "
                    String token = authorizationHeader.substring("Bearer ".length());

                    // verify the token using the algorithm that you have signed
                    // create the verifier
                    // decode the token and verify
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(token);

                    // use we have decoded the token
                    // get the username from the subject
                    // get the roles from the claim
                    // do a convention of SimpleGrantedAuthority
                    String username = decodedJWT.getSubject();

                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

                    // loop through the roles
                    // convert the roles to SimpleGrantedAuthority
                    // and add them to the Collection > authorities
                    stream(roles).forEach(role->{
                        authorities.add(new SimpleGrantedAuthority(role));
                    });

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    // this tells spring security the roles and username of the user logged in
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    filterChain.doFilter(request, response);

                }catch (Exception e){
                    
                    log.error("Error logging in: {}", e.getMessage());
                    response.setHeader("error", e.getMessage());

                    response.setStatus(FORBIDDEN.value());

                    // this will return the response in a nice JSON format
                    Map<String,String> error = new HashMap<>();
                    error.put("error_message", e.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);

                }

            }else {
                filterChain.doFilter(request, response);
            }
        }

    }
}

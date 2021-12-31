package com.techlead.userservice.api;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.techlead.userservice.model.Role;
import com.techlead.userservice.model.User;
import com.techlead.userservice.service.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static com.techlead.userservice.api.UserController.BASE_URL;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor
@RequestMapping(BASE_URL)
public class UserController {

    public static final String BASE_URL ="/api";

    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers(){

        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser( @RequestBody User user){

        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());

        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole( @RequestBody Role role){

        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());

        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/adduser")
    public ResponseEntity<?> addRoleToUser( @RequestBody RoleToUserForm form){

        userService.addRoleToUser(form.getUsername(), form.getRoleName());

        return ResponseEntity.ok().build();
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // get the header of the request
        // AUTHORIZATION - is the key we are looking for in the header
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        // check if the authorizationHeader is not null and starts with "Bearer "
        // when ever we are logged in we will pass the word "Bearer " + token
        // this mean that the user is the bearer of the token ,and we don't need to do more validations
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

            // use try in case we get an error
            try {
                // get the token by calling the header and remove the "Bearer "
                String refresh_token = authorizationHeader.substring("Bearer ".length());

                // verify the token using the algorithm that you have signed
                // create the verifier
                // decode the token and verify
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);

                // use we have decoded the token
                // get the username from the subject
                // get the roles from the claim
                // do a convention of SimpleGrantedAuthority
                String username = decodedJWT.getSubject();

                // load the user from our model
                // find the user on the database
                User user = userService.getUser(username);


                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 + 60 + 100))
                        .withIssuer(request.getRequestURI().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);


                // this will return the response in a nice JSON format
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refreshed_token", refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

            } catch (Exception e) {


                response.setHeader("error", e.getMessage());

                response.setStatus(FORBIDDEN.value());

                // this will return the response in a nice JSON format
                Map<String, String> error = new HashMap<>();
                error.put("error_message", e.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);

            }
        } else {
            throw new RuntimeException("refreshToken is missing");
        }
    }
}

@Data
class RoleToUserForm{
    private String username;
    private String roleName;
}
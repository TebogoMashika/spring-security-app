package com.techlead.userservice;

import com.techlead.userservice.model.Role;
import com.techlead.userservice.model.User;
import com.techlead.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}


	// this will be picked up when the application runs
	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){

		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));


			userService.saveUser(new User(null, "tebogo", "tebogo", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "neo", "neo", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "sophy", "sophy", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "matlou", "matlou", "1234", new ArrayList<>()));


			userService.addRoleToUser("tebogo", "ROLE_MANAGER");
			userService.addRoleToUser("tebogo", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("tebogo", "ROLE_ADMIN");
			userService.addRoleToUser("neo", "ROLE_USER");
			userService.addRoleToUser("sophy", "ROLE_USER");
			userService.addRoleToUser("matlou", "ROLE_MANAGER");


		};
	}

}

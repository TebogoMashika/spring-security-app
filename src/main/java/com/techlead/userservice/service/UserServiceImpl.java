package com.techlead.userservice.service;

import com.techlead.userservice.model.Role;
import com.techlead.userservice.model.User;
import com.techlead.userservice.repo.RoleRepository;
import com.techlead.userservice.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    // loadUserByUsername comes from the UserDetailsService interface
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);

        // check if user is null or not
        if (user == null){
            log.error("User not found in the database");

            throw  new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found in the database");
        }

         // SimpleGrantedAuthority = Stores a String representation of an authority granted to the Authentication object.
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        //
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public User saveUser(User user) {

        log.info("Saving new user {} to the database", user.getName());

        // end code the password of the user
        user.setPassword(passwordEncoder.encode(user.getPassword()));


        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to the database", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("adding role {} to  user {}" , roleName, username);

        User user = userRepo.findByUsername(username);
        Role role = roleRepository.findByName(roleName);

        user.getRoles().add(role);

        // @Transactional will save the user with the role to the database
    }

    @Override
    public User getUser(String username) {

        log.info("fetching user {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("fetching all users");
        return userRepo.findAll();
    }


}

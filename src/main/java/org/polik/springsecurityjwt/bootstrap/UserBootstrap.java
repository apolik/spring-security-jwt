package org.polik.springsecurityjwt.bootstrap;

import lombok.AllArgsConstructor;
import org.polik.springsecurityjwt.model.Role;
import org.polik.springsecurityjwt.model.User;
import org.polik.springsecurityjwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Created by Polik on 6/1/2022
 */
@Component
@AllArgsConstructor
public class UserBootstrap implements CommandLineRunner {
    private final UserService service;

    @Override
    public void run(String... args) {
        User admin = User.builder()
                .name("Amigo")
                .username("admin")
                .roles(Set.of(Role.ADMIN))
                .password("password")
                .build();

        service.create(admin);

        User user = User.builder()
                .name("D rose")
                .username("user")
                .roles(Set.of(Role.USER))
                .password("password")
                .build();

        service.create(user);
    }
}

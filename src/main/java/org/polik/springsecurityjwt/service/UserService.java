package org.polik.springsecurityjwt.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.polik.springsecurityjwt.model.Role;
import org.polik.springsecurityjwt.model.User;
import org.polik.springsecurityjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Set;

/**
 * Created by Polik on 6/1/2022
 */
@Slf4j
@Service
@Transactional(readOnly = true)
@AllArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository repository;
    private final PasswordEncoder encoder;

    public List<User> getAll() {
        log.info("getAll");
        return repository.findAll();
    }

    public User getByUsername(String username) {
        log.info("getByUsername {}", username);
        return repository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException(
                        String.format("No such user with username: %s", username))
                );
    }

    @Transactional
    public User create(User user) {
        encodePassword(user);
        user.setRoles(Set.of(Role.USER));
        log.info("create {}", user);
        return repository.save(user);
    }

    @Transactional
    public void update(User user, long id) {
        user.setId(id);
        encodePassword(user);
        log.info("update {}", user);
        repository.save(user);
    }

    @Transactional
    public void delete(long id) {
        log.info("delete {}", id);
        repository.deleteById(id);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Authenticating '{}'", username);
        User user = getByUsername(username);

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getRoles()
        );
    }

    private void encodePassword(User user) {
        Assert.notNull(user.getPassword(), "Password cannot be null");
        user.setPassword(encoder.encode(user.getPassword()));
    }
}

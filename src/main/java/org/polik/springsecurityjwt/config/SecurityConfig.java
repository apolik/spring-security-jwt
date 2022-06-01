package org.polik.springsecurityjwt.config;

import lombok.AllArgsConstructor;
import org.polik.springsecurityjwt.filter.AuthenticationFilter;
import org.polik.springsecurityjwt.filter.AuthorizationFilter;
import org.polik.springsecurityjwt.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;

/**
 * Created by Polik on 6/1/2022
 */
@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {
    private final AuthenticationConfiguration authConfiguration;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/api/v1/users/refresh-token/**").permitAll()
                .antMatchers(GET, "/api/v1/users/**").authenticated()
                .antMatchers("/api/v1/users/**").hasRole(Role.ADMIN.name())
                .and()
                .addFilter(new AuthenticationFilter(authenticationManager()))
                .addFilterBefore(new AuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authConfiguration.getAuthenticationManager();
    }
}

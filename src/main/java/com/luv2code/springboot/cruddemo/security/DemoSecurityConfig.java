package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class DemoSecurityConfig {

    //custom tables for jdbc authentication
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setUsersByUsernameQuery("SELECT user_id,pw,active FROM members where user_id=?");
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("SELECT user_id,role from roles where user_id=?");
        return jdbcUserDetailsManager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http.csrf(csrf->csrf.disable());

        http.authorizeHttpRequests(configurer->
                configurer
                        .requestMatchers(HttpMethod.GET,"api/employees").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.GET,"api/employees/**").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.POST,"api/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.PUT,"api/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.DELETE,"api/employees/**").hasRole("ADMIN")
        );
                //use http basic authentication
                http.httpBasic(Customizer.withDefaults());

                return http.build();
    }

    //Hard code users
    /*
    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){

        UserDetails john = User.builder()
                .username("john")
                .password("{noop}john123")
                .roles("EMPLOYEE")
                .build();

        UserDetails susan = User.builder()
                .username("susan")
                .password("{noop}susan123")
                .roles("EMPLOYEE","MANAGER","ADMIN")
                .build();

        UserDetails mary = User.builder()
                .username("mary")
                .password("{noop}mary123")
                .roles("EMPLOYEE","MANAGER")
                .build();

        return new InMemoryUserDetailsManager(john,susan,mary);
    }
     */

    /*
    //for bCrypt password encoding
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //configure users using database -> default spring security tables
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        return  new JdbcUserDetailsManager(dataSource);
    }

*/
}

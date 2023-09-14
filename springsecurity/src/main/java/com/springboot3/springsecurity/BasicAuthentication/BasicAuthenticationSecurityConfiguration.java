package com.springboot3.springsecurity.BasicAuthentication;

import org.slf4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

//@Configuration(proxyBeanMethods = false)
public class BasicAuthenticationSecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // to authorize every request in http
        http.authorizeHttpRequests(
                auth -> {
                    auth.anyRequest().authenticated();
                });


        // to disable sessions in http by making it stateless
        http.sessionManagement(
                session -> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS)
        );

        //http.formLogin();
        http.httpBasic(withDefaults()); // to enable basic authentication

        http.csrf(csrf -> csrf.disable()); // to disable csrf
//
//        //http.csrf(AbstractHttpConfigurer::disable);

//        http.headers(headers -> headers.frameOptions(frameOptionsConfig-> frameOptionsConfig.disable()));
//
//        // http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){

        var user = User.withUsername("userUjawall")
                .password("{noop}ujawall123")
                .passwordEncoder(str-> bCryptPasswordEncoder().encode(str))
                .roles("USER")
                .build();
        var admin= User.withUsername("adminUjawall").password("{noop}ujawall123")
                .passwordEncoder(str-> bCryptPasswordEncoder().encode(str))
                .roles("ADMIN").build();


        return new InMemoryUserDetailsManager(user,admin);
    }


    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }


}

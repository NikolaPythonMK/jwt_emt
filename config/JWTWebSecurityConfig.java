package mk.ukim.finki.emt.eshop.config;

import lombok.AllArgsConstructor;
import mk.ukim.finki.emt.eshop.config.filters.JwtAuthenticationFilter;
import mk.ukim.finki.emt.eshop.config.filters.mineFilters.JWTAuthenticationFilter;
import mk.ukim.finki.emt.eshop.config.filters.mineFilters.JWTAuthorizationFilter;
import mk.ukim.finki.emt.eshop.service.UserService;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

//@Order(200)
//@Configuration
//@Profile("jwt")
//@AllArgsConstructor
//public class JWTWebSecurityConfig extends WebSecurityConfigurerAdapter {
//
//    private final PasswordEncoder passwordEncoder;
//    private final CustomUsernamePasswordAuthenticationProvider authenticationProvider;
//    private final UserService userService;
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.cors().and().csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/", "/home", "/assets/**", "/register", "/products", "/api/**").permitAll()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .addFilter(new JwtAuthenticationFilter(authenticationManager(), userService, passwordEncoder))
//                .addFilter(new JWTAuthorizationFilter(authenticationManager(), userService))
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//
//    }
//}

@Profile("jwt")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@AllArgsConstructor
public class JWTWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "/home", "/assets/css/**", "/register", "/products", "/api/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager(), userService, passwordEncoder)) //authentication filter
                .addFilter(new JWTAuthorizationFilter(authenticationManager())) //decyption of the tokens
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}

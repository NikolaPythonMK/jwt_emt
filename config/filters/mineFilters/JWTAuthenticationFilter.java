package mk.ukim.finki.emt.eshop.config.filters.mineFilters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import mk.ukim.finki.emt.eshop.config.JwtAuthConstants;
import mk.ukim.finki.emt.eshop.model.User;
import mk.ukim.finki.emt.eshop.model.dto.UserDetailsDto;
import mk.ukim.finki.emt.eshop.model.exceptions.PasswordsDoNotMatchException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@AllArgsConstructor
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        User credentials = null;
        try{
            credentials = new ObjectMapper().readValue(request.getInputStream(), User.class);
        }
        catch (IOException e){
            e.printStackTrace();
        }
        if(credentials == null){
            throw new UsernameNotFoundException("Invalid Credentials");
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(credentials.getUsername());
        if(!passwordEncoder.matches(credentials.getPassword(), userDetails.getPassword())){
            throw new PasswordsDoNotMatchException();
        }
        return authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "", userDetails.getAuthorities()));
    }

    //na korisnikot mu go vrakjame jwt tokenot koj e soodveten za nego
    // sto da se vrati do korisnikot pri uspesno/neuspesno logiraneje
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User userDetails = (User) authResult.getPrincipal(); //.authenicate() napravi query do db, pa zatoa korisnikot go imame vo kontekstot
        String token = JWT.create()
                .withSubject(new ObjectMapper().writeValueAsString(UserDetailsDto.of(userDetails)))   //payload
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtAuthConstants.EXPIRATION_TIME))
                .sign(Algorithm.HMAC256(JwtAuthConstants.SECRET));
        response.addHeader(JwtAuthConstants.HEADER_STRING, JwtAuthConstants.TOKEN_PREFIX + token);
        response.getWriter().append(token); //za da moze react poednostavno da se snaogja, vo samoto telo go stavame tokenot
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }
}

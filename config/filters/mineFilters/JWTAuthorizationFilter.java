package mk.ukim.finki.emt.eshop.config.filters.mineFilters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import mk.ukim.finki.emt.eshop.config.JwtAuthConstants;
import mk.ukim.finki.emt.eshop.model.dto.UserDetailsDto;
import mk.ukim.finki.emt.eshop.service.UserService;
import org.eclipse.jetty.client.util.BasicAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(JwtAuthConstants.HEADER_STRING); //site headers vo ramki na java spring, site headers java spring gi precekuva i gi stava vo hash mapa
        if(header == null || !header.startsWith(JwtAuthConstants.TOKEN_PREFIX)){
            chain.doFilter(request, response);
        }

        String user = JWT.require(Algorithm.HMAC256(JwtAuthConstants.SECRET.getBytes()))
                .build()
                .verify(header.replace(JwtAuthConstants.TOKEN_PREFIX, ""))
                .getSubject();
        if(user == null){
            return;
        }
        UserDetailsDto userDetailsDto = new ObjectMapper().readValue(user, UserDetailsDto.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken
                (userDetailsDto.getUsername(), "", Collections.singleton(userDetailsDto.getRole()));
        SecurityContextHolder.getContext().setAuthentication(token);
        chain.doFilter(request, response);

    }
}

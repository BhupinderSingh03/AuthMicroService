package com.auth.security;

import com.auth.constants.AuthConstants;
import com.auth.handler.RequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Every http request will pass through this filter
 *
 *@author Bhupinder Singh
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private RequestHandler requestHandler;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /**
     * A filter responsible to validate the token request and set the authentication Security Context
     *
     * @param request for HttpServletRequest
     * @param response for HttpServletResponse
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (request.getRequestURI().contains("/signup")) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            String jwt = requestHandler.getJwtFromRequest(request);
            if (!jwt.equals("Basic")) {
                if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                    String userName = tokenProvider.getUserNameFromJWT(jwt);

                    UserDetails userDetails = customUserDetailsService.loadUserByUsername(userName);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    filterChain.doFilter(request, response);
                } else {
                    logger.error("Responding with unauthorized error. Message - {}", "token is empty");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                            AuthConstants.NOT_AUTHORISED+ "Token is empty");
                }

            }else
                filterChain.doFilter(request, response);
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);

            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    AuthConstants.NOT_AUTHORISED + ex.getMessage());
        }
    }
}

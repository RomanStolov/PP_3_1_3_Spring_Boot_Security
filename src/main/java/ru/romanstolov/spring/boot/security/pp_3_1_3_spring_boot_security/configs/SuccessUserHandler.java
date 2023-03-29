package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.configs;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

@Component
public class SuccessUserHandler implements AuthenticationSuccessHandler {

    /**
     * * ИСХОДНЫЕ ДАННЫЕ В ЗАДАЧЕ !!!
     * **********************************************************************************
     * // Spring Security использует объект Authentication, пользователя авторизованной сессии.
     *
     * @Override public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
     * HttpServletResponse httpServletResponse, Authentication authentication) throws IOException {
     * Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
     * if (roles.contains("ROLE_USER")) {
     * httpServletResponse.sendRedirect("/user");
     * } else {
     * httpServletResponse.sendRedirect("/");
     * }
     * }
     * **********************************************************************************
     * <p>
     * МОИ ДЕЙСТВИЯ:
     * - Настроил отлов в хендлере в таком порядке: ADMIN->USER->"/". (ADMIN точно должен быть первым
     * так как есть пользователи с ролями "ROLE_ADMIN" и "ROLE_USER" одновременно в утилитном классе.
     * !!!!!
     * Убрать ниже комменты в коде перед отправкой на проверку!
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication) throws IOException {
        Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
        System.out.println("* Хэндлер роли получил");
        if (roles.contains("ROLE_ADMIN")) {
            httpServletResponse.sendRedirect("/admin");
            System.out.println("* Хэндлер ADMIN`a увидел");
        } else if (roles.contains("ROLE_USER")) {
            httpServletResponse.sendRedirect("/user");
            System.out.println("* Хэндлер USER`а увидел");
        } else {
            httpServletResponse.sendRedirect("/");
            System.out.println("* Хэндлер засёк ГОСТЯ");
        }
    }

}

package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.User;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.services.UserServiceImpl;

@Configuration
//@EnableWebSecurity(debug = true)
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final SuccessUserHandler successUserHandler;

    @Autowired
    public WebSecurityConfig(SuccessUserHandler successUserHandler) {
        this.successUserHandler = successUserHandler;
    }

    /**
     * ИСХОДНЫЕ ДАННЫЕ В ЗАДАЧЕ !!!
     * **********************************************************************************
     * protected void configure(HttpSecurity http) throws Exception {
     * http
     * .authorizeRequests()
     * .antMatchers("/", "/index").permitAll()
     * .anyRequest().authenticated()
     * .and()
     * .formLogin().successHandler(successUserHandler)
     * .permitAll()
     * .and()
     * .logout()
     * .permitAll();
     * }
     * <p>
     * // аутентификация inMemory
     *
     * @Bean
     * @Override public UserDetailsService userDetailsService() {
     * UserDetails user =
     * User.withDefaultPasswordEncoder()
     * .username("user")
     * .password("user")
     * .roles("USER")
     * .build();
     * <p>
     * return new InMemoryUserDetailsManager(user);
     * }
     * **********************************************************************************
     * <p>
     * МОИ ДЕЙСТВИЯ:
     * - Разрешил всем доступ к урлам: "/registration", "/index", "/";
     * - Разрешил доступ пользователям с ролью "ROLE_ADMIN" к урлам "/admin/**";
     * - Разрешил доступ пользователям с ролями "ROLE_ADMIN" и "ROLE_USER" к урлам "/user/**";
     * - Запретил все остальные урлы для не авторизированных пользователей.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/registration", "/index", "/")
                .not().fullyAuthenticated()
                .antMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                .antMatchers("/user/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_USER")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .successHandler(successUserHandler)
                .permitAll()
                .and()
                .logout()
                .logoutSuccessUrl("/")
                .permitAll();
    }

    /**
     * Метод возвращает бин шифровщика для паролей
     * Используется мною в "UserServiceImpl" в методе "public void save(User user)":
     *
     * @see UserServiceImpl#save(User)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

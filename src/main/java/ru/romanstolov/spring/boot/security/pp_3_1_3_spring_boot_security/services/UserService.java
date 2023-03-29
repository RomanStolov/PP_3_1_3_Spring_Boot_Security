package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.Role;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.User;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Согласно условию таски, добавил имплементацию "UserDetailsService" с одним методом
 * "public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException",
 * который реализовал в "UserServiceImpl".
 * <p>
 * @see UserServiceImpl#loadUserByUsername(String)
 * <p>
 * Этот метод возвращает UserDetails - обёрнутого пользователя текущей сессии.
 */
public interface UserService extends UserDetailsService {


    Collection<Role> getListRole();

    /**
     * Добавил новый метод поиска пользователя по "username"
     * Его продублировал в интерфейс "UserRepository"
     */
    Optional<User> findByUsername(String username);

    Optional<User> findById(Long id);

    List<User> findAll();

    void save(User user);

    User getById(Long id);

    void delete(User deleteUser);

}


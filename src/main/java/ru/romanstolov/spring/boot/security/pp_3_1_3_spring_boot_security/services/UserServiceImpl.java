package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.Role;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.User;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.repositories.RoleRepository;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.repositories.UserRepository;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.utils.UserValidator;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Добавил новый метод поиска пользователя по "username"
     * Его продублировал запросом в интерфейс "UserRepository"
     * Реализовал возвращаемое значение в обёртке Optional для пригодности данного метода в классе-валидаторе
     * пользователя по имени "UserValidator". Естественно, пришлось это обёртывание учитывать в текущем классе
     * в переопределённом методе
     * "public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException".
     * <p>
     * @see UserValidator
     */
    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Добавил новый метод получения списка ВСЕХ ВОЗМОЖНЫХ ролей с обращением в "RoleRepository"
     */
    @Override
    public Collection<Role> getListRole() {
        return roleRepository.findAll();
    }

    /**
     * Реализовал метод интерфейса "UserDetailsService" унаследованного через интерфейс "UserService"
     * Этот метод возвращает UserDetails - обёрнутого пользователя текущей сессии.
     * Обеспечил генерацию требуемого исключения "UsernameNotFoundException".
     * В качестве User`a использовал не своего, а "спрингового".
     * <p>
     * ?????????????????????????????? Нужна ли здесь @Transactional? Нужно спросить у ментора.
     */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (findByUsername(username).isEmpty()) {
            throw new UsernameNotFoundException("Пользователь с таким именем не найден в БД!");
        }
        User user = findByUsername(username).get();
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                user.getRoles());
    }

    /**
     * Метод новый - добавить описание !!!
     * Пока нигде не используется.
     * Ну и пусть полежит...
     */
    @Override
    public Optional<User> findById(Long id) {
        Optional<User> optionalUser = userRepository.findById(id);
        return optionalUser;
    }

    /**
     * Переименовал метод и дал название как в репозитории
     */
    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }

    /**
     * Переименовал метод и дал название как в репозитории.
     * Этот же метод используется для "updateUser", поэтому тот метод убрал.
     * Когда мы выполняем метод save() репозитория JPARepository, то для новых сущностей вызывается persist(),
     * а для уже существующих сущностей (у которых id!=null) вызывается метод merge(). (Уточнить у ментора !).
     * В методе реализовал кодирование пользовательского пароля перед помещением пользователя в БД.
     */
    @Transactional
    @Override
    public void save(User user) {
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        userRepository.save(user);
    }

    public User getById(Long id) {
        Optional<User> optionalUser = userRepository.findById(id);
        return optionalUser.orElse(null);
    }

    /**
     * Переименовал метод и дал название как в репозитории
     */
    @Override
    @Transactional
    public void delete(User deleteUser) {
        userRepository.delete(deleteUser);
    }

}

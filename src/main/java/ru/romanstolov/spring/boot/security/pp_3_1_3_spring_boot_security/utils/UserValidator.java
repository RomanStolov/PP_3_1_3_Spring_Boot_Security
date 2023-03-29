package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.User;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.services.UserServiceImpl;

import java.util.Optional;

/**
 * Класс-валидатор для пользователя, имплементирующий Spring-интерфейс "Validator" и реализующий все его
 * ДВА методов.
 * Нужен для проверки уникальности пользовательского имени (логина в нашем случае в виде "username") при
 * регистрации нового пользователя на сайте или силами администратора, а так же при редактировании админом
 * существующего пользователя.
 */
@Component
public class UserValidator implements Validator {
    private final UserServiceImpl userService;

    @Autowired
    public UserValidator(UserServiceImpl userService) {
        this.userService = userService;
    }

    /**
     * Этот метод возвращает булево "true" в том случае если класс добавляемого объекта соответствует классу "User".
     */
    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals(clazz);
    }

    /**
     * Метод валидации.
     * В методе реализовал обращение к другому методу "public Optional<User> findUserByUsername(String username)"
     * возвращающему Optional<User> и уже от которого вызвал метод "get()" и принимаю решение о генерации ошибки
     * если не пустой вернулся Optional<User>. Наличие содержимого в Optional<User> означает что пользователь с
     * таким именем уже существует в нашей БД и тогда генерируем ошибку.
     */
    @Override
    public void validate(Object target, Errors errors) {
        User testUser = (User) target;
        Optional<User> optionalTestUser = userService.findByUsername(testUser.getUsername());
        if (optionalTestUser.isPresent()) {
            errors.rejectValue("username", "",
                    "Пользователь с таким именем уже существует! Введите другое имя!");
        }
    }

}

package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.Role;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.User;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.services.UserServiceImpl;

import java.util.Collection;
import java.util.HashSet;

/**
 * Сервисно-утилитный класс реализующий интерфейс "CommandLineRunner" для первоначального запуска
 * в Spring Boot и тестового заполнения БД пользователями.
 * Добавил в БД:
 * - одного пользователя с "ROLE_ADMIN";
 * - одного пользователя с "ROLE_USER";
 * - одного пользователя сразу с "ROLE_ADMIN" и "ROLE_USER" (для проверки функционала чисто);
 * Для того чтобы Spring Boot подхватил на старте в качестве бина и исполнил метод заполняющий первоначально
 * БД я установил аннотацию "@Component"
 */
@Component
public class InitiateUtils implements CommandLineRunner {
    private final UserServiceImpl userService;
    private final Role roleAdmin = new Role("ROLE_ADMIN");
    private final Role roleUser = new Role("ROLE_USER");

    @Autowired
    public InitiateUtils(UserServiceImpl userService) {
        this.userService = userService;
    }

    /**
     * Переопределил в текущем классе метод "public void run(String... args) throws Exception" из
     * имплементированного интерфейса "CommandLineRunner".
     * Назначил этому методу транзакцию "@Transactional", так как идёт доступ к БД с внесением изменений.
     */
    @Override
    @Transactional
    public void run(String... args) throws Exception {
        Collection<Role> rolesOnlyAdmin = new HashSet<>();
        Collection<Role> rolesOnlyUser = new HashSet<>();
        Collection<Role> rolesAdminAndUser = new HashSet<>();

        rolesOnlyAdmin.add(roleAdmin);
        rolesOnlyUser.add(roleUser);
        rolesAdminAndUser.add(roleUser);
        rolesAdminAndUser.add(roleAdmin);


        userService
                .save(new User("admin", "SurnameAdmin", (byte) 100, "email_admin@mail.ru", "admin", rolesOnlyAdmin));
        userService
                .save(new User("user1", "Surname1", (byte) 10, "email_1@mail.ru", "password1", rolesOnlyUser));
        userService
                .save(new User("user2", "Surname2", (byte) 20, "email_2@mail.ru", "password2", rolesOnlyUser));
        userService
                .save(new User("user3", "Surname3", (byte) 30, "email_3@mail.ru", "password3", rolesOnlyUser));
        userService
                .save(new User("user4", "Surname4", (byte) 40, "email_4@mail.ru", "password4", rolesOnlyUser));
        userService
                .save(new User("user5", "Surname5", (byte) 50, "email_5@mail.ru", "password5", rolesAdminAndUser));
    }

}

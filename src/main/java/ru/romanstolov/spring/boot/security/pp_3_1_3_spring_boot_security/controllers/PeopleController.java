package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.Role;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.User;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.services.UserServiceImpl;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.utils.UserValidator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Ссылка на главную страничку, чтоб в браузере пальчиками не корячиться...
 * http://localhost:8080/
 * Решил не заморачиваться с двумя контроллерами и запихал всё в один "развязав" доступ пафу префиксами
 * админа и юзера.
 */
@Controller
public class PeopleController {
    private final UserServiceImpl userService;
    private final UserValidator userValidator;

    @Autowired
    public PeopleController(UserServiceImpl userService, UserValidator userValidator) {
        this.userService = userService;
        this.userValidator = userValidator;
    }

    /**
     * Метод возвращающий страницу регистрации нового пользователя на сайте.
     */
    @GetMapping(value = "/registration")
    public String registrationForm(@ModelAttribute(value = "registrUser") User registrUser) {
        return "registration";
    }

    /**
     * Метод сохраняющий нового пользователя в БД со страницы регистрации нового пользователя на сайте.
     * По умолчанию автоматически присваивается новому пользователю при регистрации на сайте роль "ROLE_USER".
     * Ещё дополнительно реализована валидация пользователя по уникальности имени (логина). Если ошибки при
     * вводе имени нового пользователя, то возврат обратно на форму регистрации!
     */
    @PutMapping(value = "/registration")
    public String registrationPutUser(@Validated @ModelAttribute(value = "registrUser") User registrUser,
                                      BindingResult bindingResult) {
        Role role = new Role("ROLE_USER");
        Collection<Role> roles = new ArrayList<>();
        roles.add(role);
        registrUser.setRoles(roles);
        userValidator.validate(registrUser, bindingResult);
        if (bindingResult.hasErrors()) {
            return "registration";
        }
        userService.save(registrUser);
        return "redirect:/login";
    }

    /**
     * Метод возвращающий страницу с информацией о пользователе (пользователе или администраторе).
     */
    @GetMapping(value = "/user")
    public String getUserInfoPage(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String currentUserName = userDetails.getUsername();
        User currentUser = userService.findByUsername(currentUserName).get();
        model.addAttribute("currentUser", currentUser);
        return "user/user";
    }

    /**
     * Метод администратора возвращающий список всех пользователей и саму форму.
     */
    @GetMapping(value = "/admin/users")
    public String getAllUsers(Model model) {
        List<User> listUsers = userService.findAll();
        model.addAttribute("listUsers", listUsers);
        return "admin/crud/users";
    }

    /**
     * Метод администратора возвращающий форму регистрации нового пользователя.
     * Подгрузил полный список всех возможных ролей для выбора на форме разных вариантов
     * при установки полномочий при добавлении нового пользователя.
     */
    @GetMapping(value = "/admin/users/new")
    public String getNewForm(Model model) {
        model.addAttribute("newUser", new User());
        Collection<Role> listAllRoles = userService.getListRole();
        model.addAttribute("listAllRoles", listAllRoles);
        return "admin/crud/user-new";
    }

    /**
     * Метод администратора сохраняющий нового пользователя в БД с формы регистрации нового пользователя.
     * После добавления пользователя в БД делаю редирект обратно на страницу админа со списком всех
     * пользователей.
     * Выполняется предварительная проверка на наличие пользователя в БД с таким же Username как и у вновь
     * регистрируемого пользователя (уникальность логина в БД). Если ошибки при вводе имени нового пользователя,
     * то возврат обратно на форму регистрации!
     */
    @PutMapping(value = "/admin/users")
    public String putUser(@Validated @ModelAttribute(value = "newUser") User newUser,
                          BindingResult bindingResult) {
        userValidator.validate(newUser, bindingResult);
        if (bindingResult.hasErrors()) {
            return "admin/crud/user-new";
        }
        userService.save(newUser);
        return "redirect:/admin/users";
    }

    /**
     * Метод администратора возвращающий форму редактирования пользователя.
     * Подгрузил полный список всех возможных ролей для выбора на форме разных вариантов для установки
     * полномочий при добавлении нового пользователя.
     */
    @GetMapping(value = "/admin/users/{id}/edit")
    public String getEditForm(@PathVariable("id") Long id, Model model) {
        User editUser = userService.getById(id);
        Collection<Role> listAllRoles = userService.getListRole();
        model.addAttribute("editUser", editUser);
        model.addAttribute("listAllRoles", listAllRoles);
        return "admin/crud/user-id-edit";
    }

    /**
     * Метод администратора сохраняющий в БД измененную информацию о пользователе с формы редактирования.
     * После сохранения отредактированного пользователя делаю редирект обратно на страницу админа со списком
     * всех пользователей.
     */
    @PatchMapping(value = "/admin/users/{id}")
    public String patchUser(@Validated @ModelAttribute(value = "editUser") User editUser) {
        userService.save(editUser);
        return "redirect:/admin/users";
    }

    /**
     * Метод администратора удаляющий пользователя из БД.
     * Использовал "id" удаляемого пользователя для создания нового пользователя и затем отправки его
     * с этим установленным "id" в сервис на удаление.
     * После удаления пользователя по "id" делаю редирект обратно на страницу админа со списком всех
     * пользователей.
     */
    @DeleteMapping(value = "/admin/users/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        User user = new User();
        user.setId(id);
        userService.delete(user);
        return "redirect:/admin/users";
    }

}

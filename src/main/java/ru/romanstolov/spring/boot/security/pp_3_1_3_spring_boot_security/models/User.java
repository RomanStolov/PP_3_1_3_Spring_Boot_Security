package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.utils.InitiateUtils;

import javax.persistence.*;
import javax.validation.constraints.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * МОИ ДЕЙСТВИЯ:
 * <p>
 * - Добавил имплементацию "UserDetails" и реализовал в классе все его СЕМЬ методов.
 * <p>
 * - Реализовал связь между таблицей пользователей "users" и таблицей ролей "roles" как "многие-ко-многим",
 * причём двунаправленную. Связующая третья таблица "users_roles" создаётся автоматически.
 * <p>
 * - Добавил каскад "cascade = {CascadeType.PERSIST, CascadeType.MERGE}" над полем со списком ролей. "CascadeType" -
 * этот параметр определяет, что должно происходить с зависимыми сущностями, если мы меняем главную сущность.
 * В JPA спецификации есть такие значения этого параметра:
 * .    - ALL - все действия, которые мы выполняем с родительским объектом, нужно повторить и для его зависимых
 * .            объектов.
 * .    - PERSIST - если мы сохраняем в базу родительский объект, то это же нужно сделать и с его зависимыми
 * .            объектами.
 * .    - MERGE - если мы обновляем в базе родительский объект, то это же нужно сделать и с его зависимыми объектами.
 * .    - REMOVE (DELETE) - если мы удаляем в базе родительский объект, то это же нужно сделать и с его зависимыми
 * .            объектами.
 * .    - REFRESH (SAVE_UPDATE) - дублируют действия, которые выполняются с родительским объектом к его зависимому
 * .            объекту.
 * .    - DETACH - если мы удаляем родительский объект из сессии, то это же нужно сделать и с его зависимыми объектами.
 * Однако Hibernate расширяет эту спецификацию еще на три варианта:
 * .    - REPLICATE
 * .    - SAVE_UPDATE
 * .    - LOCK
 * <p>
 * - Указал "ленивую" загрузку "fetch = FetchType.LAZY" над полем со списком ролей. Параметр fetch позволяет управлять
 * режимами загрузки зависимых объектов. Обычно он принимает одно из двух значений: FetchType.LAZY или FetchType.EAGER.
 * <p>
 * - Добавил валидацию данных над полями "на стороне сервера" - так надёжнее чем на стороне клиента.
 * <p>
 * - В двунаправленные отношения добавил методы синхронизации "addRole()" и "removeRole()" для поддержания
 * согласованности ссылок. Чтобы не было ситуации, когда у пользователя есть такая-то роль в коллекции,
 * а у роли нет в коллекции этого пользователя.
 */
@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @NotNull
    @Size(min = 3, max = 25, message = "Введите имя(логин) длиною от 3 до 25 символов!")
    private String username;
    @NotNull
    @Size(min = 1, max = 25, message = "Введите фамилию длиною от 1 до 25 символов!")
    private String surname;
    @Min(value = 1, message = "Введите значение возраста от 1 до 110!")
    @Max(value = 110, message = "Введите значение возраста от 1 до 110!")
    private Byte age;
    @Email(message = "Введите правильный адрес почты!")
    private String email;
    @NotEmpty(message = "Введите пароль длиною от 5 до 30 символов!")
    private String password;
    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE}, fetch = FetchType.LAZY)
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Collection<Role> roles = new HashSet<>();

    public User() {

    }

    /**
     * Конструктор необходимый лишь для того чтоб изначально заполнить БД с использованием утилитного класса
     * "InitiateUtils implements CommandLineRunner"
     *
     * @see InitiateUtils
     */
    public User(String username, String surname, Byte age, String email, String password, Collection<Role> roles) {
        this.username = username;
        this.surname = surname;
        this.age = age;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }

    /**
     * Метод добавления роли пользователю.
     * Дополнительно идёт добавление пользователя к роли.
     */
    public void addRole(Role role) {
        this.roles.add(role);
        role.getUsers().add(this);
    }

    /**
     * Метод удаления роли у пользователя.
     * Дополнительно идёт удаление пользователя у роли.
     */
    public void removeRole(Role role) {
        this.roles.remove(role);
        role.getUsers().remove(this);
    }

    /**
     * Реализовал метод получения списка ролей пользователя в текстовом виде для отображения на форме.
     * В тестовом режиме работы программы пришлось делать проверку на случай если роль не установить.
     * Подрихтовал стрингу на выходе.
     */
    public String getRole() {
        if (roles.isEmpty()) {
            return "";
        }
        String answerRoles = roles.stream()
                .map(Role::getName)
                .map(r -> (r.substring(5) + "; "))
                .collect(Collectors.joining());
        return answerRoles.substring(0, answerRoles.length() - 2);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    /**
     * В этом переопределённом методе прописал возврат authorities пользователя в виде List<SimpleGrantedAuthority>
     * представляющего собою ArrayList<SimpleGrantedAuthority> сделанный из Set<Role> текущего пользователя.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return authorities;
    }

    /**
     * В этом переопределённом методе прописал "true"
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Переименовал у себя в классе "name" в "username"
     * В этом переопределённом методе прописал возврат "username"
     */
    @Override
    public String getUsername() {
        return username;
    }

    /**
     * В этом переопределённом методе прописал "true"
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * В этом переопределённом методе прописал "true"
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * В этом переопределённом методе прописал "true"
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * В этом переопределённом методе прописал "true"
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public Byte getAge() {
        return age;
    }

    public void setAge(Byte age) {
        this.age = age;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Collection<Role> getRoles() {
        return roles;
    }

    public void setRoles(Collection<Role> roles) {
        this.roles = roles;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return username.equals(user.username) && surname.equals(user.surname);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, surname);
    }

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", surname='" + surname + '\'' +
                ", age=" + age +
                ", email='" + email + '\'' +
                ", roles=" + roles +
                '}';
    }

}

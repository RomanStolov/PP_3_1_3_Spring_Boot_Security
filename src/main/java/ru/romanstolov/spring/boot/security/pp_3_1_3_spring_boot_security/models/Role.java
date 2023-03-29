package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Роль является неглавной стороной, поэтому коллекция пользователей аннотирована "mappedBy"
 */
@Entity
@Table(name = "roles")
public class Role implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @NotEmpty
    private String name;
    @ManyToMany(mappedBy = "roles")
    private Set<User> users = new HashSet<>();

    public Role() {

    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    /**
     * В этом переопределённом методе прописал возврат "name" для нашей роли
     */
    @Override
    public String getAuthority() {
        return name;
    }

    public Role(String name) {
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /**
     * Переопределил метод принимая во внимание, что поле в классе "User" вот такое:
     * "private Collection<Role> roles = new HashSet<>();".
     * Для того чтобы имена ролей отображались в форме сделал определение иквэлс в зависимости
     * только от "name".
     * И equals() и hashCode() должны быть переопределены, чтобы Spring MVC и Thymeleaf
     * правильно отображали флажки, когда форма находится в режиме редактирования.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        return name.equals(role.name);
    }

    /**
     * Переопределил метод принимая во внимание, что поле в классе "User" вот такое:
     * "private Collection<Role> roles = new HashSet<>();".
     * Для того чтобы имена ролей отображались в форме сделал подсчёт хэшкода в зависимости
     * только от "name".
     * И equals() и hashCode() должны быть переопределены, чтобы Spring MVC и Thymeleaf
     * правильно отображали флажки, когда форма находится в режиме редактирования.
     */
    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    /**
     * Переопределил и оставил только само имя
     */
    @Override
    public String toString() {
        return name;
    }

}

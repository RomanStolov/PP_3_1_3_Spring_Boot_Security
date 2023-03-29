package ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.romanstolov.spring.boot.security.pp_3_1_3_spring_boot_security.models.Role;

/**
 * Прикольно, что тут можно самому написывать любые методы задавая параметры метода и тип возвращаемого значения
 * при совершенно произвольном наименовании самого метода!
 * Этот интерфейс расширяет интерфейс JpaRepository из Spring Data JPA. JpaRepository определяет стандартные
 * методы CRUD, а также операции, специфичные для JPA. Нам не нужно писать код реализации, потому что Spring
 * Data JPA сгенерирует необходимый код во время выполнения в виде прокси-экземпляров.
 * Цель написания интерфейса репозитория - сообщить Spring Data JPA о типе домена (Role) и типе идентификатора
 * (Long) для работы.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

}

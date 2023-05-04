package pdp.uz.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pdp.uz.domain.Role;
import pdp.uz.domain.enums.RoleEnum;

@Repository
public interface RoleRepository extends JpaRepository<Role,Integer> {
    Role findByRoleNames(RoleEnum roleNames);
}

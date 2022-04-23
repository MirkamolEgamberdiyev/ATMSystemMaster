package pdp.uz.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pdp.uz.domain.Commission;
import pdp.uz.domain.enums.OperationType;

import java.util.Optional;

@Repository
public interface CommissionRepo extends JpaRepository<Commission, Long> {

    Optional<Commission> findByAdditionalAndKey(boolean additional, OperationType key);
}

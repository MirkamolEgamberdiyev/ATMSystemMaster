package pdp.uz.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pdp.uz.domain.ATM;

public interface ATMRepo extends JpaRepository<ATM, Long> {
}

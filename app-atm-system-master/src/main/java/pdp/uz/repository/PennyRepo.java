package pdp.uz.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pdp.uz.domain.Penny;

@Repository
public interface PennyRepo extends JpaRepository<Penny, Long> {
}

package pdp.uz.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import pdp.uz.domain.Card;

import java.util.Optional;

@Repository
public interface CardRepo extends JpaRepository<Card, Long> {

    Optional<Card> findByNumber(String number);

    boolean existsByNumber(String number);

    @Query("select c from Card c where c.number = ?1 and c.active = true and c.blocked = false")
    Optional<Card> findActiveCard(String username);
}

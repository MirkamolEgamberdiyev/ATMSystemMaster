package pdp.uz.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pdp.uz.domain.Card;
import pdp.uz.domain.Employee;
import pdp.uz.repository.CardRepo;
import pdp.uz.repository.EmployeeRepo;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final EmployeeRepo employeeRepo;

    private final CardRepo cardRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (cardRepo.existsByNumber(username)) {
            Optional<Card> optionalCard = cardRepo.findActiveCard(username);
            if (!optionalCard.isPresent())
                throw new UsernameNotFoundException("Card not found");
            Card card = optionalCard.get();
            card.setAttempts(0);
            cardRepo.save(card);
            return new User(card.getNumber(), card.getPassword(), new HashSet<>());
        }
        Optional<Employee> optionalEmployee = employeeRepo.findByEmail(username);
        if (!optionalEmployee.isPresent())
            return null;
        Employee employee = optionalEmployee.get();
        Collection<GrantedAuthority> authorities = new HashSet<>();
        employee.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName().name())));
        return new User(employee.getEmail(), employee.getPassword(), authorities);
    }
}

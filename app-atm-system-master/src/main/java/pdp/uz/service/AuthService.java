package pdp.uz.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import pdp.uz.domain.Card;
import pdp.uz.payload.ApiResponse;
import pdp.uz.payload.LoginDto;
import pdp.uz.repository.CardRepo;
import pdp.uz.security.JWTProvider;

import javax.transaction.Transactional;
import java.util.Optional;

@Service
@Transactional
public class AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTProvider jwtProvider;

    @Autowired
    private CardRepo cardRepo;

    public ApiResponse login(LoginDto dto) {
        Optional<Card> optionalCard = cardRepo.findActiveCard(dto.getLogin());
        try {
            if (optionalCard.isPresent()){
                Card card = optionalCard.get();
                if (Card.checkValidity(card.getExpiry())){
                    card.setActive(false);
                    cardRepo.save(card);
                }
            }
            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getLogin(), dto.getPassword()));
            User user = (User) authenticate.getPrincipal();
            String token = jwtProvider.generateToken(user.getUsername(), user.getAuthorities());
            return new ApiResponse("OK", true, token);
        } catch (BadCredentialsException e) {
            if (optionalCard.isPresent()) {
                Card card = optionalCard.get();
                card.setAttempts(card.getAttempts() + 1);
                if (card.getAttempts() == 3)
                    card.setBlocked(true);
                cardRepo.save(card);
            }
            return new ApiResponse("Login or password incorrect", false);
        }
    }
}

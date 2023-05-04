package pdp.uz.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pdp.uz.config.SecurityConfig;
import pdp.uz.domain.Card;
import pdp.uz.domain.User;
import pdp.uz.domain.enums.RoleEnum;
import pdp.uz.payload.ApiResponse;
import pdp.uz.payload.LoginDto;
import pdp.uz.payload.UserDto;
import pdp.uz.repository.CardRepo;
import pdp.uz.repository.RoleRepository;
import pdp.uz.repository.UserRepository;
import pdp.uz.security.JWTProvider;

import javax.transaction.Transactional;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTProvider jwtProvider;

    @Autowired
    private CardRepo cardRepo;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    RoleRepository roleRepository;

    @Autowired
    SecurityConfig securityConfig;

    public ApiResponse login(LoginDto dto) {
        Optional<Card> optionalCard = cardRepo.findActiveCard(dto.getLogin());
        try {
            if (optionalCard.isPresent()) {
                Card card = optionalCard.get();
                if (Card.checkValidity(card.getExpiry())) {
                    card.setActive(false);
                    cardRepo.save(card);
                }
            }
            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getLogin(), dto.getPassword()));
            User user = (User) authenticate.getPrincipal();
            String token = jwtProvider.generateToken(user.getUsername(), user.getRoles());
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

    public ApiResponse register(UserDto userDto) {
        if (userRepository.existsByEmail(userDto.getEmail())) {
            return new ApiResponse("This email already exist", false);
        }
        User user = new User();
        user.setFirstname(userDto.getFirstname());
        user.setLastname(userDto.getLastname());
        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setRoles(Collections.singleton(roleRepository.findByRoleNames(RoleEnum.ROLE_DIRECTOR)));
        user.setEmailCode(UUID.randomUUID().toString());
        String link = "http://localhost:8080/api/verifyEmail?emailCode=%s&email=%s"
                .formatted(user.getEmailCode(), user.getEmail());
        if (securityConfig.sendMessage(user.getEmail(), link)) {
            userRepository.save(user);
            return new ApiResponse("User Saved verify accaunt", true);
        }
        System.out.println(SecurityContextHolder.getContext().getAuthentication());
        return new ApiResponse("User not verify", false);
//        SecurityContextHolder.getContext().getAuthentication().getPrincipal()

    }

    public ApiResponse verifyEmail(String emailCode, String email) {
        Optional<User> optionalUser = userRepository.findByEmailCodeAndEmail(emailCode, email);
        if (!optionalUser.isPresent())
            return new ApiResponse("Accaunt oldin tasdiqlangan", false);

        if (!optionalUser.get().isEnabled()) {
            User user = optionalUser.get();
            user.setEnabled(true);
            user.setEmailCode(null);
            userRepository.save(user);
            return new ApiResponse("Accaunt tasdiqlandi", true);
        }
        return new ApiResponse("Accaunt oldin tasdiqlangan", false);
    }
}

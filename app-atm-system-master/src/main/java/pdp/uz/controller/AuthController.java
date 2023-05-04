package pdp.uz.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pdp.uz.payload.ApiResponse;
import pdp.uz.payload.LoginDto;
import pdp.uz.payload.UserDto;
import pdp.uz.service.AuthService;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public HttpEntity<?> register(@RequestBody UserDto userDto) {
        ApiResponse register = authService.register(userDto);
        return ResponseEntity.status(register.isStatus() ? 201 : 409).body(register.getMessage());
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginDto dto) {
        ApiResponse apiResponse = authService.login(dto);
        return ResponseEntity.status(apiResponse.isStatus() ? 200 : 401).body(apiResponse);
    }

    @PostMapping("/verifyEmail")
    public HttpEntity<?> verifyEmail(@RequestParam String emailCode, @RequestParam String email) {
        ApiResponse verifyEmail = authService.verifyEmail(emailCode, email);
        return ResponseEntity.status(verifyEmail.isStatus() ? HttpStatus.OK : HttpStatus.UNAUTHORIZED).body(verifyEmail.getMessage());
    }


}

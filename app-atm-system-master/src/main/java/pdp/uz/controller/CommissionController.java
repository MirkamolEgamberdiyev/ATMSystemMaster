package pdp.uz.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pdp.uz.payload.ApiResponse;
import pdp.uz.payload.CommissionDto;
import pdp.uz.service.CommissionService;

@RestController
@RequestMapping( "/api/commission")
@RequiredArgsConstructor
public class CommissionController {

    private final CommissionService commissionService;

    @PostMapping("/setSame/bank")
    @PreAuthorize("hasRole('ROLE_DIRECTOR')")
    public ResponseEntity<?> setSameBankCommission(@RequestBody CommissionDto dto) {
        ApiResponse apiResponse = commissionService.setSameBankCommission(dto);
        return ResponseEntity.status(apiResponse.isStatus() ? 200 : 400).body(apiResponse);
    }

}

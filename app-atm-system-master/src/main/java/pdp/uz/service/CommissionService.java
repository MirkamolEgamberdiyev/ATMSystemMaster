package pdp.uz.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pdp.uz.domain.Commission;
import pdp.uz.domain.enums.OperationType;
import pdp.uz.payload.ApiResponse;
import pdp.uz.payload.CommissionDto;
import pdp.uz.repository.CommissionRepo;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class CommissionService {

    private final CommissionRepo commissionRepo;

    public ApiResponse setSameBankCommission(CommissionDto dto) {
        try {
            Optional<Commission> optionalCommission = commissionRepo.findByAdditionalAndKey(dto.isSameBank(), OperationType.valueOf(dto.getKey()));
            if (!optionalCommission.isPresent()) {
                return new ApiResponse("Commission not found", false);
            }
            Commission commission = optionalCommission.get();
            commission.setValue(dto.getValue());
            commissionRepo.save(commission);
        } catch (Exception e) {
            return new ApiResponse("Operation type format is not correct (Use PUT or GET)", false);
        }
        return null;
    }
}

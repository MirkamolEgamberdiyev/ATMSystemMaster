package pdp.uz.payload;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import pdp.uz.domain.enums.OperationType;

import java.time.LocalDateTime;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ATMHistoryRespDto {

    private String details;

    private boolean fromEmployee = false;

    private OperationType operation;

    private Long atm;

    private LocalDateTime createdAt = LocalDateTime.now();
}

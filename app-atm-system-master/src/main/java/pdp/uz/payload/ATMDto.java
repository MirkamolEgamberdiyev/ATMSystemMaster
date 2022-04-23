package pdp.uz.payload;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ATMDto {

    @NotNull
    private Long maxLimit;

    @NotNull
    private Long minLimit;

    @NotNull
    private String address;

    @NotNull
    @ApiModelProperty(example = "UZCARD")
    private String cardType;

    @NotNull
    private String bankCode;

    @NotNull
    private Long employeeId;
}

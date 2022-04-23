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
public class PennyDto {

    @NotNull
    @ApiModelProperty(example = "UZS")
    private String currency;

    @NotNull
    @ApiModelProperty(example = "1000")
    private String penny;

    @NotNull
    @ApiModelProperty(example = "100")
    private Integer quantity;
}

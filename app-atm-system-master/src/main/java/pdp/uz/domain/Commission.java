package pdp.uz.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import pdp.uz.domain.enums.OperationType;

import javax.persistence.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Commission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private boolean additional = true;  // true -> karta banki bilan bankomat banki bitta,    false -> har xil

    @Enumerated(EnumType.STRING)
    private OperationType key;

    @Column
    private String value;
}

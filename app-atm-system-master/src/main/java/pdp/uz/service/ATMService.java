package pdp.uz.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import pdp.uz.domain.ATM;
import pdp.uz.domain.ATMHistory;
import pdp.uz.domain.Employee;
import pdp.uz.domain.Penny;
import pdp.uz.domain.enums.CardType;
import pdp.uz.domain.enums.OperationType;
import pdp.uz.payload.ATMDto;
import pdp.uz.payload.ApiResponse;
import pdp.uz.payload.FillDto;
import pdp.uz.payload.LimitDto;
import pdp.uz.repository.*;

import javax.mail.internet.MimeMessage;
import javax.transaction.Transactional;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class ATMService {

    private final ATMRepo atmRepo;

    private final ATMHistoryRepo atmHistoryRepo;

    private final EmployeeRepo employeeRepo;

    private final CommissionRepo commissionRepo;

    private final PennyRepo pennyRepo;

    private final JavaMailSender mailSender;


    public ApiResponse getIntervalReport(String from, String to, Long id) {
        try {
            LocalDateTime start = LocalDateTime.of(LocalDate.parse(from), LocalTime.of(0, 0, 0));
            LocalDateTime end = LocalDateTime.of(LocalDate.parse(to), LocalTime.of(0, 0, 0));
            if (!atmRepo.existsById(id)) {
                return new ApiResponse("ATM not found", false);
            }
            List<ATMHistory> histories = atmHistoryRepo.getIntervalReport(id, start, end);

            return new ApiResponse("OK", true, histories);
        } catch (Exception e) {
            return new ApiResponse("Date format is not correct. (Use YYYY-MM-DD", false);
        }
    }

    public void sendEmail(ATM atm) {
        String body = "<h1>The money in the ATM has reached the limit</h1>" +
                "<p><b>Address: </b> " + atm.getAddress() + "</p>" +
                "<p><b>Limit: </b> " + atm.getMinLimit() + "</p>" +
                "<p><b>Balance: </b> " + Penny.calculatePennies(atm.getPennies()) + "</p>";
        try {
            String from = "testovtestjonbek@gmail.com";
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message);
            helper.setSubject("The money in the ATM has reached the limit");
            helper.setFrom(from);
            helper.setText(body, true);
            helper.setTo(atm.getEmployee().getEmail());
            mailSender.send(message);
        } catch (Exception ignored) {
        }
    }

    public ApiResponse getIntervalInputReport(Long id) {
        if (!atmRepo.existsById(id)) {
            return new ApiResponse("ATM not found", false);
        }
        LocalDate now = LocalDate.now();
        List<ATMHistory> histories = atmHistoryRepo.getIntervalReportOp(id, LocalDateTime.of(now, LocalTime.MIN),
                LocalDateTime.of(now.plusDays(1), LocalTime.MIN), OperationType.PUT);
        return new ApiResponse("OK", true, histories);
    }

    public ApiResponse getIntervalOutputReport(Long id) {
        if (!atmRepo.existsById(id)) {
            return new ApiResponse("ATM not found", false);
        }
        LocalDate now = LocalDate.now();
        List<ATMHistory> histories = atmHistoryRepo.getIntervalReportOp(id, LocalDateTime.of(now, LocalTime.MIN),
                LocalDateTime.of(now.plusDays(1), LocalTime.MIN), OperationType.GET);
        return new ApiResponse("OK", true, histories);
    }

    public ApiResponse getPenniesReport(Long id) {
        if (!atmRepo.existsById(id)) {
            return new ApiResponse("ATM not found", false);
        }
        ATM atm = atmRepo.getById(id);
        return new ApiResponse("OK", true, atm.getPennies());
    }

    public ApiResponse getFillReport(Long id) {
        if (!atmRepo.existsById(id)) {
            return new ApiResponse("ATM not found", false);
        }
        List<ATMHistory> histories = atmHistoryRepo.getFillReport(id);
        return new ApiResponse("OK", true, histories);
    }

    public ApiResponse register(ATMDto dto) {
        try {
            Optional<Employee> optionalEmployee = employeeRepo.findById(dto.getEmployeeId());
            if (!optionalEmployee.isPresent()) {
                return new ApiResponse("Employee not found", false);
            }
            ATM atm = new ATM();
            atm.setAddress(dto.getAddress());
            atm.setBankCode(dto.getBankCode());
            atm.setMaxLimit(dto.getMaxLimit());
            atm.setMinLimit(dto.getMinLimit());
            atm.setCommissions(commissionRepo.findAll());
            atm.setCardType(CardType.valueOf(dto.getCardType()));
            Employee employee = optionalEmployee.get();
            atm.setEmployee(employee);
            ATM save = atmRepo.save(atm);
            employee.getAtms().add(save);
            employeeRepo.save(employee);
            return new ApiResponse("Created", true);
        } catch (Exception e) {
            return new ApiResponse("Card type format is not correct. (Use UZCARD, HUMO, VISA)", false);
        }
    }

    public ApiResponse fill(FillDto dto) {
        try {
            Optional<ATM> optionalATM = atmRepo.findById(dto.getAtmId());
            if (!optionalATM.isPresent()) {
                return new ApiResponse("ATM not found", false);
            }
            ATM atm = optionalATM.get();
            Employee employee = employeeRepo.findByEmail(Employee.getCurrentEmployee().getUsername()).get();
            if (!employee.getAtms().contains(atm)) {
                return new ApiResponse("You do not have access", false);
            }
            List<Penny> pennies = Penny.toPenny(dto.getPennies());

            List<Penny> atmPennies = atm.getPennies();
            for (Penny penny : pennies) {
                boolean hasPenny = false;
                for (Penny atmPenny : atmPennies) {
                    if (!penny.getCurrency().equals(atmPenny.getCurrency())) {
                        return new ApiResponse("You put wrong currency", false);
                    }
                    if (penny.getKey().equals(atmPenny.getKey())) {
                        atmPenny.setValue(atmPenny.getValue() + penny.getValue());
                        hasPenny = true;
                    }
                }
                if (!hasPenny) {
                    atmPennies.add(penny);
                    pennyRepo.save(penny);
                }
            }
            Map<String, String> details = Penny.toDetail(pennies, atm);
            details.put("Sum", String.valueOf(Penny.calculatePennies(pennies)));

            atmHistoryRepo.save(ATMHistory.createHistory(OperationType.PUT, atm, details, true));
            return new ApiResponse("Pennies added", true);
        } catch (Exception e) {
            return new ApiResponse("Currency type format is not correct use UZS, USD", false);
        }
    }

    public ApiResponse setMaxLimit(LimitDto dto) {
        List<ATM> atmList = atmRepo.findAll();
        for (ATM atm : atmList) {
            atm.setMaxLimit(dto.getLimit());
        }
        atmRepo.saveAll(atmList);
        return new ApiResponse("OK", true);
    }

    public ApiResponse setMaxLimit(Long id, LimitDto dto) {
        Optional<ATM> optionalATM = atmRepo.findById(id);
        if (!optionalATM.isPresent()) {
            return new ApiResponse("ATM not found", false);
        }
        ATM atm = optionalATM.get();
        atm.setMaxLimit(dto.getLimit());
        atmRepo.save(atm);
        return new ApiResponse("OK", true);
    }

    public ApiResponse setMinLimit(LimitDto dto) {
        List<ATM> atmList = atmRepo.findAll();
        for (ATM atm : atmList) {
            atm.setMinLimit(dto.getLimit());
        }
        atmRepo.saveAll(atmList);
        return new ApiResponse("OK", true);
    }

    public ApiResponse setMinLimit(Long id, LimitDto dto) {
        Optional<ATM> optionalATM = atmRepo.findById(id);
        if (!optionalATM.isPresent()) {
            return new ApiResponse("ATM not found", false);
        }
        ATM atm = optionalATM.get();
        atm.setMinLimit(dto.getLimit());
        atmRepo.save(atm);
        return new ApiResponse("OK", true);
    }
}

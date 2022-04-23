package pdp.uz.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pdp.uz.domain.Employee;
import pdp.uz.domain.enums.RoleEnum;
import pdp.uz.payload.ApiResponse;
import pdp.uz.payload.EmployeeDto;
import pdp.uz.repository.EmployeeRepo;
import pdp.uz.repository.RoleRepo;

import javax.transaction.Transactional;

@Service
@Transactional
public class EmployeeService {

    @Autowired
    private EmployeeRepo employeeRepo;

    @Autowired
    private RoleRepo roleRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;


    public ApiResponse register(EmployeeDto dto) {
        if (employeeRepo.existsByEmail(dto.getEmail())) {
            return new ApiResponse("Employee already existed", false);
        }
        Employee employee = new Employee();
        employee.setEmail(dto.getEmail());
        employee.setFullName(dto.getFullName());
        employee.setPassword(passwordEncoder.encode(dto.getPassword()));
        employee.getRoles().add(roleRepo.findByName(RoleEnum.ROLE_EMPLOYEE.name()));
        employeeRepo.save(employee);
        return new ApiResponse("OK", true);
    }
}

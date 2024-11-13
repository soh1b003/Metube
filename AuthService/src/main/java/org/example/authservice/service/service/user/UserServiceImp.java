package org.example.authservice.service.service.user;

import lombok.RequiredArgsConstructor;


import org.example.authservice.domain.entity.UserEntity;

import org.example.authservice.domain.request.LoginDTO;
import org.example.authservice.domain.response.UserResponse;
import org.example.authservice.exception.BaseException;
import org.example.authservice.repository.UserRepository;
import org.example.authservice.service.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

import org.example.authservice.domain.request.UserRequest;
import org.example.authservice.domain.response.JwtResponse;

@Service
@RequiredArgsConstructor
public class UserServiceImp implements UserService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserResponse saveUser(UserRequest userRequest) {
        if (userRepository.findByUsername(userRequest.getUsername()).isPresent()) {
            throw new BaseException("Username already exists");
        }

        UserEntity userEntity = UserEntity.builder()
                .username(userRequest.getUsername())
                .password(passwordEncoder.encode(userRequest.getPassword()))
                .email(userRequest.getEmail())
                .picturePath(userRequest.getPicturePath())
                .build();

        userRepository.save(userEntity);


        return UserResponse.builder()
                .username(userEntity.getUsername())
                .email(userEntity.getEmail())
                .build();


    }

    @Override
    public UserResponse updateUser(UUID id, UserRequest userRequest) {
        UserEntity userEntity = userRepository.findById(id).orElseThrow(() -> new BaseException("User not found"));
        userEntity.setUsername(userRequest.getUsername());
        userEntity.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        userEntity.setEmail(userRequest.getEmail());
        userEntity.setPicturePath(userRequest.getPicturePath());
        userRepository.save(userEntity);

        return UserResponse.builder()
                .username(userEntity.getUsername())
                .email(userEntity.getEmail())
                .build();
    }

    @Override
    public void deleteUser(UUID id) {
        userRepository.deleteById(id);
    }

    @Override
    public UserResponse findById(UUID id) {
        UserEntity userEntity = userRepository.findById(id).orElseThrow(() -> new BaseException("User not found"));

        return UserResponse.builder()
                .username(userEntity.getUsername())
                .email(userEntity.getEmail())
                .build();
    }

    @Override
    public List<UserResponse> getAllUsers() {
        return userRepository.getAllUsers();
    }

    @Override
    public JwtResponse login(LoginDTO loginDTO) {
        UserEntity userEntity = userRepository.findByUsername(loginDTO.getUsername()).orElseThrow(() -> new BaseException("user not found"));
        if (!passwordEncoder.matches(loginDTO.getPassword(), userEntity.getPassword())) {
            throw new BaseException("wrong password");
        }

        return new JwtResponse(jwtService.generateAccessToken(userEntity),
                jwtService.generateRefreshToken(userEntity));
    }
}

package com.upgrad.technical.service.business;


import com.auth0.jwt.JWT;
import com.upgrad.technical.service.dao.UserDao;
import com.upgrad.technical.service.entity.UserAuthTokenEntity;
import com.upgrad.technical.service.entity.UserEntity;
import com.upgrad.technical.service.exception.AuthenticationFailedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;

@Service
public class AuthenticationService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private PasswordCryptographyProvider CryptographyProvider;

    @Transactional(propagation = Propagation.REQUIRED)
    public UserAuthTokenEntity authenticate(final String username, final String password) throws AuthenticationFailedException {
        UserEntity userEntity = userDao.getUserByEmail(username);

        if(userEntity == null)
            throw new AuthenticationFailedException("ATH-001", "User with email not found.");


        final String encryptedPassword = CryptographyProvider.encrypt(password, userEntity.getSalt());
        if(encryptedPassword.equals(userEntity.getPassword())){
            JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(encryptedPassword);
            UserAuthTokenEntity userAuthToken = new UserAuthTokenEntity();
            userAuthToken.setUser(userEntity);
            final ZonedDateTime now = ZonedDateTime.now();
            final ZonedDateTime expiresAt = now.plusHours(9);

            userAuthToken.setAccessToken(jwtTokenProvider.generateToken(userEntity.getUuid(), now , expiresAt));
            userAuthToken.setExpiresAt(expiresAt);
            userAuthToken.setLoginAt(now);
            userDao.createAuthToken(userAuthToken);
            userEntity.setLastLoginAt(now);
            userDao.updateUser(userEntity);

            return userAuthToken;
        }
        else
            throw new AuthenticationFailedException("ATH-002", "Password failure");
    }
}



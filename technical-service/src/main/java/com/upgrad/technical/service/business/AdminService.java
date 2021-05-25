package com.upgrad.technical.service.business;


import com.upgrad.technical.service.dao.ImageDao;
import com.upgrad.technical.service.dao.UserDao;
import com.upgrad.technical.service.entity.ImageEntity;
import com.upgrad.technical.service.entity.UserAuthTokenEntity;
import com.upgrad.technical.service.exception.ImageNotFoundException;
import com.upgrad.technical.service.exception.UnauthorizedException;
import com.upgrad.technical.service.exception.UserNotSignedInException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;

@Service
public class AdminService {

    @Autowired
    private ImageDao imageDao;
    //Get Image
    public ImageEntity getImage(final String imageUuid, final String authorization) throws ImageNotFoundException, UnauthorizedException, UserNotSignedInException {

        UserAuthTokenEntity userAuthTokenEntity = imageDao.getUserAuthToken(authorization);

        if(userAuthTokenEntity == null)
            throw new UserNotSignedInException("\"USR-001","You are not Signed in, sign in first to get the details");

        String role = userAuthTokenEntity.getUser().getRole();

        if(!role.equals("admin"))
        {
            throw new UnauthorizedException("ATH-001", "UNAUTHORIZED Access, Entered user is an admin.");
        }

        ImageEntity findImage = imageDao.getImage(imageUuid);

        if(findImage == null)
            throw new ImageNotFoundException("IMG-001", "Image with Uuid not found");
        return findImage;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public ImageEntity updateImage(final ImageEntity imageEntity, final String authorization) throws ImageNotFoundException, UnauthorizedException, UserNotSignedInException {
        UserAuthTokenEntity userAuthTokenEntity = imageDao.getUserAuthToken(authorization);

        if(userAuthTokenEntity == null)
            throw new UserNotSignedInException("USR-001", "You are not Signed in, sign in first to get the details");
        String role = userAuthTokenEntity.getUser().getRole();

        if(!role.equals("admin"))
            throw new UnauthorizedException("ATH-001", "UNAUTHORIZED Access, Entered user is not an admin.");

        ImageEntity updateImage = imageDao.getImageById(imageEntity.getId());
        if(updateImage == null)
            throw new ImageNotFoundException("IMG-001", "Image with Id not found.");

        updateImage.setImage(imageEntity.getImage());
        updateImage.setStatus(imageEntity.getStatus());
        updateImage.setDescription(imageEntity.getDescription());
        updateImage.setName(imageEntity.getName());

        imageDao.updateImage(updateImage);
        return updateImage;
    }
}

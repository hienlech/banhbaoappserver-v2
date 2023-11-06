const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const authMiddleware = require('../../middleware/auth');
const axios = require('axios');
//Model
const User = require('../../models/User');

const Room = require('../../models/Database');

const facebookApi = 'https://graph.facebook.com/me?fields=email,birthday,link,first_name,id,last_name,gender,picture&access_token=';

// @route POST api/auth
// @desc Authenticate An User
// @access Public
router.post('/', (req, res) => {
    let {
        username,
        password,
        token_device 
    } = req.body;
    //Simple validation
    if (!username || !password) {
        return res.status(400).json({
            status: '400',
            msg: 'Please enter both username and password!',
        });
    }

    username = username.toLowerCase();

    //Check for existing user
    User.findOne({
        username,
    }).then((user) => {
        if (!user) {
            return res.status(401).json({
                status: 401,
                msg: 'User does not exists',
            });
        } else {
            validatePass(res, password, user,token_device);
        }
    });
});




function validatePass(res, password, user,token_device) {
    //Validate password
    bcrypt.compare(password, user.password).then((isMatch) => {
        if (!isMatch)
            return res.status(401).json({
                status: 401,
                msg: 'Password is incorect!',
            });
        jwt.sign({
                id: user.id,
                username: user.username,
                token_device : token_device
            },
            config.get('jwtSecret'), {
                expiresIn: 8640000,
            },
            (err, token,token_device) => {
                if (err) {
                    return res.status(401).json({
                        status: 401,
                        msg: 'failed valid token',
                    });
                }
                const responseUser = {
                    token,
                    token_device,
                    _id: user._id,
                    username: user.username,
                };
                return  res.status(200).json({
                    status: 200,
                    user: responseUser,
                });
            },
        );
    });
}

// @route POST api/auth/me
// @desc Get user data
// @access Private
router.get('/me', authMiddleware, (req, res) => {
    User.findById(req.user.id)
        .select('-password')
        .then((User) => {
            res.json({
                status: 200,
                User,
            });
        });
});
router.post('/facebook', async(req, res, next) => {
    try {
        const accessToken = req.body.access_token;
        const token_device = req.body.token_device;
        const url = facebookApi + accessToken;
        const datares = await axios.get(url);
        let datajson = datares.data;

        if (!datajson) {
            res.json({
                status: 401,
                msg: 'Auth failed',
            });
        }
        //Check for existing user
        User.findOne({
            facebook_id: datajson.id,
        }).then((user) => {
            if (!user) {
                const newUser = new User({
                    username: datajson.id,
                    firstname: datajson.first_name,
                    lastname: datajson.last_name,
                    email: datajson.email,
                    gender: datajson.gender,
                    dob: datajson.birthday,
                    facebook_id: datajson.id,
                    picture: datajson.picture.data.url,
                });
                newUser.save().then((user) => {
                    jwt.sign({
                            id: user.id,
                            username: user.username,
                            token_device
                        },
                        config.get('jwtSecret'), {
                            expiresIn: 8640000,
                        },
                        (err, token) => {
                            if (err) {
                                console.log('failed bcrypt jwt');
                                return res.status(401).json({
                                    status: 401,
                                    msg: 'jwt failed',
                                });
                            }
                            return res.status(200).json({
                                status: 200,
                                first: 1,
                                user: {
                                    token,
                                    _id: user.id,
                                    username: user.username,
                                    token_device
                                },
                            });
                        },
                    );
                });
            } else {
                jwt.sign({
                        id: user.id,
                        username: user.username,
                        token_device
                    },
                    config.get('jwtSecret'), {
                        expiresIn: 8640000,
                    },
                    (err, token) => {
                        if (err) {
                            console.log('failed bcrypt jwt');
                            return res.status(401).json({
                                status: 401,
                                msg: 'jwt failed',
                            });
                        }
                        return res.status(200).json({
                            status: 200,
                            first: 0,
                            user: {
                                _id: user.id,
                                username: user.username,
                                token,
                            },
                        });
                    },
                );
            }
        });
    } catch (err) {
        console.log(err);
        res.json({
            status: 401,
            msg: 'Auth failed',
        });
    }
});



const decodedToken = token => jwt.verify(token, config.get("jwtSecret"));

router.post('/logout',  async(req, res) => {
    //const token = req.header("auth-token");
    let {
        token 
    } = req.body;
    if (!token || token == "null" || token == "" || token == null || token == undefined) {
        console.log("token invalid in logout:", token);
        return res.json({
            status: 400,
            msg: 'token invalid',
        });
    }
    
    const { username, id,  token_device } = decodedToken(token);
    const room = await Room.findRoomAndRemoveToken(token_device);
    console.log('logout******>>',room);
    return res.json({
        status: 200,
        msg: 'Done',
    });

 })




module.exports = router;
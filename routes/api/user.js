const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const authMiddleware = require('../../middleware/auth');
const validate = require("../../middleware/validate");
const Link = require('../../models/Link');
const User = require('../../models/User');
const Feedback = require('../../models/Feedback');
const ResetPass = require('../../models/resetPass');
const ALPHABET = '0123456789';

const RoomDetails = require("../../models/Database");

// @route POST api/user
// @desc Create An User
// @access Public

router.post('/', validate.valiEmailUser, (req, res) => {

    let {
        username,
        password,
        firstname,
        lastname,
        email,
        dob,
        gender,
        token_device
    } = req.body;



    const newUser = new User({
        username,
        password,
        firstname,
        lastname,
        email,
        gender,
        dob,
    });
    createUser(res, newUser, token_device);

});

function createUser(res, newUser, token_device) {
    //Create salt and hash
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) {
                return res.status(401).json({
                    status: 401,
                    msg: 'bcrypt password failed',
                });
            }
            newUser.password = hash;
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
                            return res.status(401).json({
                                status: 401,
                                msg: 'jwt failed',
                            });
                        }
                        return res.status(200).json({
                            status: 200,
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
        });
    });
}

// @route GET api/user/:couple_id
// @desc Sync User couple Id
// @access Public
router.get('/', authMiddleware, (req, res) => {
    const condition = {
        _id: req.user.id,
    };
    User.findOne(condition)
        .select('-password')
        .then((user) => {
            if (user) {
                return res.status(200).json({
                    status: 200,
                    user: user,
                });
            } else {
                return res.status(400).json({
                    status: 400,
                    msg: 'Get user infor failed',
                });
            }
        });
});

function checkDate(dob) {
    let time = new Date();
    let now = new Date(time.getFullYear(), time.getMonth(), time.getDate());
    let dateArr = dob.split('/');
    let dateOfBirth = new Date(dateArr[2], dateArr[0], dateArr[1]);
    let check = (now - dateOfBirth) / (1000 * 60 * 60 * 24 * 365);
    if (check >= 13) return true;
    else return false;
}
// @route POST api/user/update
// @desc Create An User
// @access Public

const emailRegexp = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
router.post('/update', authMiddleware, (req, res) => {
    var condition = {
        _id: req.user.id,
    };
    let { email, dob } = req.body;
    if (!emailRegexp.test(email)) {
        return res.status(400).json({
            status: 400,
            msg: 'Email is not in the correct format, minimum length of 3, up to 22',
        });
    }
    if (!checkDate(dob)) {
        return res.status(400).json({
            status: 400,
            msg: 'Age must be 13+',
        });
    }
    updateUser(condition, req.body)
        .then((updatedUser) =>
            res.json({
                status: 200,
                user: updatedUser,
            }),
        )
        .catch((err) =>
            res.json({
                status: 400,
                msg: 'Update failed',
            }),
        );
});

const updateUser = (condition, updateBody) => {
    return User.findOneAndUpdate(condition, updateBody, {
        new: true,
    }).select('-password');
};
router.post("/remove-room-close", authMiddleware, async(req, res) => {
    const {key } = req.body
    if(key == config.get('key')) {
        const r = await RoomDetails.findAndClean(1);
        res.json({
            status: 200,
            msg: r,
        })
    }
    else {
        res.json({
            status: 400,
            msg: 'failed',
        })
    }
})

// @route POST api/user/password
// @desc Change password
// @access Public
router.post('/password', authMiddleware, (req, res) => {
    var _id = req.user.id;
    let {
        password,
        new_password
    } = req.body;

    if (!password || !new_password) {
        return res.status(400).json({
            status: '400',
            msg: 'Please enter both password!',
        });
    }

    User.findById({
        _id
    }).then((user) => {
        if (!user) {
            console.log('user not exist');
            return res.status(401).json({
                status: 401,
                msg: 'Username or Password is incorect!',
            });
        } else {
            validatePass(res, _id, password, user, new_password);
        }
    });
});

function validatePass(res, _id, password, user, new_password) {
    //Validate password
    bcrypt.compare(password, user.password).then((isMatch) => {
        if (!isMatch)
            return res.status(401).json({
                status: 401,
                msg: 'Username or Password is incorect!',
            });
        updatePass(res, _id, new_password);
    });
}

function updatePass(res, _id, new_password) {
    //Create salt and hash
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(new_password, salt, (err, hash) => {
            if (err) {
                return res.status(401).json({
                    status: 401,
                    msg: 'bcrypt password failed',
                });
            }
            new_password = hash;
            User.update({
                _id,
            }, {
                password: new_password,
            },
                function (err, affected, resp) {
                    return res.json({
                        status: 200,
                        msg: 'Update success',
                    });
                },
            );
        });
    });
}

// @route POST api/user/feedback
// @desc send feedback
// @access Public
router.post('/feedback', authMiddleware, (req, res) => {
    var user_id = req.user.id;
    let {
        title,
        feedback
    } = req.body;
    if (!feedback) {
        return res.status(400).json({
            status: 400,
            msg: 'Please enter both feedback!',
        });
    }
    var time = new Date();
    const newFeedback = new Feedback({
        user_id,
        title,
        feedback,
        time,
    });
    newFeedback.save().then((feedback) => {
        if (feedback) {
            return res.status(200).json({
                status: 200,
                msg: 'Feedback success',
            });
        } else {
            return res.status(400).json({
                status: 400,
                msg: 'Feedback failed',
            });
        }
    });
});
// @route POST api/user/getlinkconfessionorgroupfb
// @desc get link confession or group
// @access Public
router.get('/getlinkconfessionorgroupfb', async (req, res) => {
    try {
        const links = await Link.find();
        if (links.length != 0) {
            return res.status(200).json({
                status: 200,
                links,
            });
        } else {
            return res.status(404).json({
                status: 404,
                msg: 'Not Found',
            });
        }
    } catch (error) {
        return res.status(400).json({
            status: 400,
            msg: 'Link group and confession failed',
        });
    }
});
//random code

function generate() {
    let id = '';
    for (let i = 0; i < 6; i++) {
        id += ALPHABET.charAt(Math.floor(Math.random() * ALPHABET.length));
    }
    return id;
}

router.post('/getcode', async (req, res) => {

    const email = req.body.email;
    console.log('email:', email);
    console.log('req.body.email:', req.body.email);

    const resetPass = await ResetPass.find({
        email
    });
    console.log('resetPass', resetPass);
    const user = await User.findOne({
        email
    });
    if (!user) {
        return res.status(404).json({
            status: 404,
            msg: 'email not found',
        });
    }
    _id = user._id;
    const mailUser = email;
    const code = generate();
    if (resetPass.length != 0) {
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(code, salt, async (err, hash) => {
                if (err) {
                    return res.status(401).json({
                        status: 401,
                        msg: 'bcrypt code failed',
                    });
                }
                await ResetPass.findOneAndUpdate({
                    email
                }, {
                    enCode: hash
                });
            });
        });
    } else {
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(code, salt, async (err, hash) => {
                if (err) {
                    return res.status(401).json({
                        status: 401,
                        msg: 'bcrypt code failed',
                    });
                }
                await ResetPass.create({
                    email: mailUser,
                    userId: _id,
                    enCode: hash,
                });
            });
        });
    }
    try {
        sendmail(mailUser, code);
        console.log('We sent code to', mailUser);
        return res.status(200).json({
            status: 200,
            msg: 'We sent code to your email'
        });
    } catch (error) {
        console.log('We sent code Erorr', error);
        return res.status(401).json({
            status: 401,
            msg: 'Sent code fail',
        });
    }
});
// @route POST api/user/resetPassword/:userId
// @desc send code to email user
// @access Public
router.post('/resetpassword', async (req, res) => {
    const email = req.body.email;
    const resetPass = await ResetPass.find({
        email
    });
    console.log('resetPass', resetPass);
    const user = await User.findOne({
        email
    });
    if (!user) {
        return res.status(404).json({
            status: 404,
            msg: 'email not found',
        });
    }
    _id = user._id;
    const mailUser = email;
    const code = generate();
    if (resetPass.length != 0) {
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(code, salt, async (err, hash) => {
                if (err) {
                    return res.status(401).json({
                        status: 401,
                        msg: 'bcrypt code failed',
                    });
                }
                await ResetPass.findOneAndUpdate({
                    email
                }, {
                    enCode: hash
                });
            });
        });
    } else {
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(code, salt, async (err, hash) => {
                if (err) {
                    return res.status(401).json({
                        status: 401,
                        msg: 'bcrypt code failed',
                    });
                }
                await ResetPass.create({
                    email: mailUser,
                    userId: _id,
                    enCode: hash,
                });
            });
        });
    }
    try {
        sendmail(mailUser, code);
        console.log('We sent code to', mailUser);
        return res.status(200).json({
            status: 200,
            msg: 'We sent code to your email'
        });
    } catch (error) {
        console.log('We sent code Erorr', error);
        return res.status(401).json({
            status: 401,
            msg: 'Sent code fail',
        });
    }
});

router.post('/email', async (req, res) => {
    const email = req.body.email;
    const resetPass = await ResetPass.find({
        email
    });

    console.log('resetPass', resetPass);
    let user = await User.findOne({
        email
    });

    if (!user) {
        user = new User({
            email
        });

        await user.save();
    }

    _id = user._id;
    const mailUser = email;
    const code = generate();

    if (resetPass.length != 0) {
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(code, salt, async (err, hash) => {
                if (err) {
                    return res.status(401).json({
                        status: 401,
                        msg: 'bcrypt code failed',
                    });
                }
                await ResetPass.findOneAndUpdate({
                    email
                }, {
                    enCode: hash
                });
            });
        });
    } else {
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(code, salt, async (err, hash) => {
                if (err) {
                    return res.status(401).json({
                        status: 401,
                        msg: 'bcrypt code failed',
                    });
                }
                await ResetPass.create({
                    email: mailUser,
                    userId: _id,
                    enCode: hash,
                });
            });
        });
    }
    try {
        sendmail(mailUser, code);
        console.log('We sent code to', mailUser);
        return res.status(200).json({
            status: 200,
            msg: 'We sent code to your email'
        });
    } catch (error) {
        console.log('We sent code Erorr', error);
        return res.status(401).json({
            status: 401,
            msg: 'Sent code fail',
        });
    }
});

async function sendmail(mailUser, code) {
    let transporter = nodemailer.createTransport({
        host: 'stmp.larksuite.com',
        port: 465,
        secure: true,
        auth: {
            user: config.get('email'),
            pass: config.get('pass'),
        },
    });
    await transporter.sendMail({
        from: config.get('email'),
        to: mailUser,
        subject: config.get("subject"),
        text: config.get("text") + code
    });
}

router.post('/confirm', async (req, res) => {
    const {
        code,
        email
    } = req.body;
    const resetCode = await ResetPass.findOne({
        email,
    });
    const user = await User.findOne({
        email,
    });
    const userId = user._id;

    if (!resetCode) {
        console.log('resetCode fail');
        return res.status(404).json({
            status: 404,
            msg: 'Code not found',
        });
    }
    let enCode = resetCode.enCode;
    const match = await bcrypt.compare(code, enCode);
    if (!match) {
        console.log('resetCode not match');
        return res.status(404).json({
            status: 404,
            msg: 'Code Fail',
        });
    }
    return res.status(200).json({
        status: 200,
        msg: 'Confirm code OK',
        // userId: userId
    });
});

router.post('/check_otp', async (req, res) => {
    const {
        code,
        email,
        token_device
    } = req.body;

    const resetCode = await ResetPass.findOne({
        email,
    });

    const user = await User.findOne({
        email,
    });

    const userId = user._id;

    if (!resetCode) {
        console.log('resetCode fail');
        return res.status(404).json({
            status: 404,
            msg: 'Code not found',
        });
    }
    let enCode = resetCode.enCode;
    const match = await bcrypt.compare(code, enCode);
    if (!match) {
        console.log('resetCode not match');
        return res.status(404).json({
            status: 404,
            msg: 'Code Fail',
        });
    }

    // remove if exist and authenticate success
    await ResetPass.findOneAndRemove({
        email,
    });
    
    jwt.sign({
        id: user.id,
        email: user.email,
        token_device
    },
        config.get('jwtSecret'), {
        expiresIn: 8640000,
    },
        (err, token) => {
            if (err) {
                return res.status(401).json({
                    status: 401,
                    msg: 'jwt failed',
                });
            }
            return res.status(200).json({
                status: 200,
                user: {
                    token,
                    _id: user.id,
                    email: user.email,
                    token_device
                },
            });
        },
    );
});

router.post('/changepassword', async (req, res) => {
    const {
        email,
        code,
        password
    } = req.body;
    const resetCode = await ResetPass.findOne({
        email
    });
    if (!resetCode) {
        return res.status(404).json({
            status: 404,
            msg: 'Code or email not found',
        });
    }
    let enCode = resetCode.enCode;
    const match = await bcrypt.compare(code, enCode);
    if (!match) {
        return res.status(404).json({
            status: 404,
            msg: 'Code or email not found',
        });
    }
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, async (err, hash) => {
            if (err) {
                console.log(err);
                return res.status(401).json({
                    status: 401,
                    msg: 'bcrypt code failed',
                });
            }
            try {
                await User.findOneAndUpdate({
                    email,
                }, {
                    password: hash,
                });
                await ResetPass.findOneAndRemove({
                    email,
                });
                return res.status(200).json({
                    status: 200,
                    msg: 'Changed password',
                });
            } catch (error) {
                return res.status(404).json({
                    status: 404,
                    msg: 'Code or email not found',
                });
            }
        });
    });
});

//-----------------delete user---------------------

router.post('/remove', async (req, res) => {
    const {
        email,
        code
    } = req.body;
    console.log('remove user:', req.body);
    const resetCode = await ResetPass.findOne({
        email
    });
    console.log('confirm code to remove:', resetCode);
    if (!resetCode) {
        return res.status(404).json({
            status: 404,
            msg: 'Code or email not found',
        });
    }
    let enCode = resetCode.enCode;
    console.log('enCode:', enCode);
    const match = await bcrypt.compare(code, enCode);
    if (!match) {
        return res.status(404).json({
            status: 404,
            msg: 'Code or email not found',
        });
    }
    else {
        
        await User.findOneAndRemove({ email });
        await ResetPass.findOneAndRemove({ email });
        return res.status(200).json({
            status: 200,
            msg: 'Changed password',
        });
    }
    
});
module.exports = router;
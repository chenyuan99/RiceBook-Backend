const md5 = require('md5');
const cookieParser = require('cookie-parser')
const session = require('express-session')
const bodyParser = require('body-parser')
const mongoose = require("mongoose");
let userObjs = {};
const User = require('./model.js').User
const Profiles = require('./model.js').Profiles
const connectionString = 'mongodb+srv://yc149:Lovelife098!@cluster0.hqe6q.mongodb.net/social?retryWrites=true&w=majority';
const mySecretMessage = "test yc149"
const salt = Math.random() * 1000;
const redis = require("redis");
var cookieKey = 'sid'
const fs = require("fs");
const client = redis.createClient("redis://:pecb97496a2e8074497b485fda26cbdd6aef129eb2e8451481b80e7f97698fb57@ec2-34-204-225-229.compute-1.amazonaws.com:31320", {
    tls: {
        rejectUnauthorized: false
    }
});

function isLoggedIn(req, res, next) {
    const sid = req.cookies[cookieKey]
    if (!sid) {
        return res.sendStatus(401)
    }
    client.hget(sid, "username", function (err, username) {
        if (username) {
            req.username = username
            next()
        } else {
            res.status(401).send('User session not exist')
        }
    })
}

function login(req, res) {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    // console.log(userObjs);
    var username = req.body.username
    var password = req.body.password
    if (!username || !password) {
        res.status(400).send("Missing input username or password")
        return
    }
    User.find({username: username}).exec(function (err, users) {
        if (users.length == 0) {
            res.status(401).send("this username is not registered yet.")
            return
        }
        const userObj = users[0]
        if (userObj == null) {
            res.status(401).send("Username is missing in the database")
        }
        const salt = userObj.salt
        const hash = userObj.hash
        const newhash = md5(password + salt)
        if (newhash != hash) {
            res.status(401).send("Password is wrong!")
        } else {
            const sessionKey = md5(mySecretMessage + new Date().getTime() + userObj.username)
            client.hmset(sessionKey, "username", username)
            res.cookie(cookieKey, sessionKey, {maxAge: 3600 * 1000, httpOnly: true})
            const msg = {username: username, result: 'success'}
            res.send(msg)
        }
    })
}

function register(req, res) {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    let username = req.body.username;
    let password = req.body.password;
    let email = req.body.email;
    let dob = new Date(req.body.dob).getTime();
    let zipcode = req.body.zipcode;
    if (!username || !password || !email || !dob || !zipcode) {
        res.status(400).send({result: "Missing inputs"});
        return;
    }
    User.find({username: username}, function (err, users) {
        if (users.length !== 0) {
            res.status(401).send("username already registered")
            return
        }
        let hash = md5(password + salt);
        let userobj = new User({username: username, salt: salt, hash: hash})
        const profileObj = new Profiles({
            username: username,
            email: email,
            dob: dob,
            zipcode: zipcode,
            headline: "dummy headline",
            following: [],
            avatar: ""
        })
        userobj.save();
        profileObj.save();
        res.status(200).send({
            result: 'success',
            username: username
        });
    })
}

function logout(req, res) {
    const sid = req.cookies[cookieKey]
    client.del(sid)
    res.clearCookie(cookieKey)
    res.status(200).send('OK')
}

const putPassword = (req, res) => {
    const newPassword = req.body.password
    const username = req.username
    if (newPassword == null) {
        res.status(400).send("Password  missing")
        return
    }
    User.find({username: username}, function (err, users) {
        const userObj = users[0]
        const salt = userObj.salt
        const newSalt = md5(salt + new Date().getTime())
        const newHash = md5(newPassword + newSalt)
        User.updateMany(
            {username: username},
            {$set: {salt: newSalt, hash: newHash}},
            {new: true},
            function (err, profile) {
                res.status(200).send("password successfully changed")
            })
    })

}


module.exports = (app) => {
    app.use(cookieParser());
    app.post('/register', register);
    app.post('/login', login);
    app.use(isLoggedIn);
    app.put('/logout', logout);
    app.put('/password', putPassword);
}


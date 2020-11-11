const express = require('express');
const bcrypt = require("bcryptjs");
const router = express.Router();
const User = require("../models/User.model")
const saltRounds = 10;
/* GET home page */

function requireLogin(req, res, next){
    if(req.session.currentUser){
      next();
    }else{
      res.redirect("/login");
    }
}

router.get('/', (req, res, next) => res.render('index', {user: req.session.currentUser}));

router.get("/register", (req, res) => {
    res.render("register")
})

router.post("/register", (req, res) => {
    let { username, password } = req.body;
    const salt = bcrypt.genSaltSync(saltRounds);
    const hashPassword = bcrypt.hashSync(password, salt);
    if (username === "" || password === "") {
        res.render("register",
            {
                errorMessage: "Indicade Username and Password"
            })
        return;

    } else {
        User.findOne({ "username": username })
            .then((user) => {
                if (user) {
                    res.render("register",
                        {
                            errorMessage: "Username already exits"
                        })
                    return;
                }
                User.create({ username, password: hashPassword })
                    .then(() => {
                        res.redirect("/")
                    })
            })
    }
})

router.get("/login", (req, res) => {
    res.render("login")
})

router.post("/login", (req, res) => {
    let { username, password } = req.body;
    if (username === "" || password === "") {
        res.render("login",
            {
                errorMessage: "Indicade Username and Password"
            })
        return;
    }
    User.findOne({ "username": username })
        .then((user) => {
            if (!user) {
                res.render("login",
                    {
                        errorMessage: "Invalid login"
                    })
                return;
            }
            if(bcrypt.compareSync(password, user.password)){
                req.session.currentUser = user;
                res.redirect("/")
            }else{
                res.render("login", 
                {
                    errorMessage: "Invalid login"
                })
            }
        })

})

router.post("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
})

router.get("/main", requireLogin, (req, res) => {
    res.render("main")
})

router.get("/private", requireLogin, (req, res) => {
    res.render("private")
})

module.exports = router;

const express = require("express");

// for hashing the password
const bcrypt = require("bcryptjs");
const salt = bcrypt.genSaltSync(10);

// routing
const router = express.Router();

// import the user schema
const User = require("../model/user");

const jwt = require('jsonwebtoken');

router.post("/register",async(req,res)=>{
    try{
        const plainPassword = req.body.password;   
        if (plainPassword.length < 5){
            return res.json({
                status: '500',
                error: 'Password too small. Should be atleast 6 characters'
            });
        } 
        if(!req.body.name || !req.body.email || !req.body.role)
        {
            return res.json({
                status: '500',
                error: 'all fields should fill prperly'
            });
        }    
        const hash = bcrypt.hashSync(plainPassword,salt);         // hashing password
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            role: req.body.role,
            password: hash
        });
        const saveUser = await user.save();
        res.status(201).send(saveUser);
    }catch(err){
        res.status(500).send("Error occured in register");
    }
});

router.post("/login",async (req,res)=>{
    try{
        const existUser = await User.findOne({email:req.body.email});
       
        if(existUser){
            const checkUser = bcrypt.compareSync(req.body.password, existUser.password);
            if(checkUser){
                // token genertaor
               const token= jwt.sign({data:req.body.email}, process.env.KEY,{ expiresIn: '1h'});
               res.send(token);
            }else{
                res.send("Invalid password");
            }
        }
        else{
            res.send("User does not exist");
        }
    }catch(err){
        res.send(err);
    }
});

module.exports = router;

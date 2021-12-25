const express = require("express");
const router = express.Router();

// authenticate
const jwt = require('jsonwebtoken');

// for hashing the password
const bcrypt = require("bcryptjs");
const salt = bcrypt.genSaltSync(10);

// import the user schema
const User = require("../model/user");

// update the details
router.patch("/:id",tokenVerify, async (req, res)=>{
    try{
        const user = await User.findOne({_id:req.params.id});
        const checkManager = await User.findOne({email:req.token});

        // check the user wheather manager or user
        if(checkManager.role === "user"){          
            if(req.token !== user.email ){
            res.send("enter your vaild token/id");
            return;
            }
        }     
        if(req.body.password){
            const plainPassword = req.body.password;
            const hash = bcrypt.hashSync(plainPassword,salt); 
            req.body.password = hash;
        }
        const id = req.params.id;
        const updates = req.body;
        const result = await User.findByIdAndUpdate(id,updates,{new: true});
        res.send(result);
    }
    catch(err){
        res.send("check your id");
    }
});

//middleware
function tokenVerify (req, res, next) {
   try{
         // Get auth header value
        const bearerHeader = req.headers['authorization'];
        if(typeof bearerHeader === 'undefined'){
            res.send("enter your token");
            return;
         }
        // Check if bearer is undefined
        if(typeof bearerHeader !== 'undefined') {
            // Split at the space
            const bearer = bearerHeader.split(' ');
            // Get token from array
            const bearerToken = bearer[1];
            // Set the token
            req.token = bearerToken;
            // token validator
            const data = jwt.verify(req.token,process.env.KEY);
            if(data){
                //console.log(data.data);
                req.token = data.data;
                next();
                return;
            }
        else{
            res.send("enter your Token")
            return;
        }
    }
    else{
        res.send("Token Invalid")
        return;
    }
   }
   catch(err){
       res.send(err);
   }
};


//delete the user
router.delete("/:id",tokenVerify,async(req,res)=>{
    try{
        const user = await User.findOne({_id:req.params.id});
        const checkManager = await User.find({email:req.token});

        if(checkManager.role === "user"){
            if(req.token !== user.email ){
                res.send("enter your vaild token");
                return;
            }
        }      

        User.findByIdAndRemove(req.params.id, function (err, docs) {
            if (err){
                res.send(err);
            }
            else{
            res.send("Removed successfully");
            }
        });
    }
    catch(err){
        res.send("check your id");
    }
});

// get user details
router.get("/:id",tokenVerify, async (req,res)=>{
    const user = await User.findOne({_id:req.params.id});
    const checkManager = await User.find({email:req.token});

    if(checkManager.role === "user"){
        if(req.token !== user.email ){
        res.send("enter your vaild token");
        return;
        }
    }      
    res.send(user);
});

module.exports = router;
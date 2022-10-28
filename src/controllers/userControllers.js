import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { Jwt } from "jsonwebtoken";
import { userSchema } from '../models/userModel'
import e from "express";

const User = mongoose.model("User", userSchema);

//this function check if user logdin or not
export const loginRequired = (req, res, next) => {
    //if we have login user
    if(req.user) {
        next();
    } else {
        //this user is not into db
        return res.states(401).json({message: 'Unauthorised user!'});
    }
}

//create new user
export const register = (req, res) => {
    //mongooseで作ってuserSchemaをPassingしたものでこんどは新しいUserを作る！
    const newUser = new User(req.body)
    //databaseにPassする前にbcryptする前にdecodeしてPassingする！
    newUser.hashPassword = bcrypt.hashSync(req.body.password, 10);
    //mongoにdataをsave！
    newUser.save((err,user) => {
        if(err) {
            return res.status(400).send({
                message:err
            });
        } else {
            //passswordをpassing backしないからここはundefinedを送る
            user.hashPassword = undefined;
            return res.json(user);
        }
    })
}
export const login = (req, res) => {
    //Find email from database
    User.findOne({
        email: req.body.email
    },(err, user) => {
        if(err) throw err;
        if(!user) {
            res.status(401).json({message: 'authentication failed. nouser found'});
        //userを見つけたら
        } else if(user) {
            if(!user.comparePassword(req.body.password, user.hashPassword))
            res.status(401).json({ message: 'authentication failed. Wrong password'});
        } else {
            //send a token back here
            return res.json({token: jwt.sign({email: user.email, username: user.username, _id: user.id},'RESTFUL APIs')})
            //このRESTFUL ALISのところはIWTが送られたらこれを合図として表示する。secretなのでなんでもいい
        }
    })
}
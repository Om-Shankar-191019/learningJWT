import UserModel from "../models/User.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import transporter from "../config/emailConfig.js";

class UserController{
    static userRegistration = async (req,res) => {
        const { name, email, password, password_confirmation, tc } = req.body;
        const user = await UserModel.findOne({email:email});
        if(user){
            res.send({"status":"failed", "message":"Email already exists"});
        }else{
            if(name && email && password && password_confirmation && tc ){
                if(password === password_confirmation){
                    try{
                        const salt = await bcrypt.genSalt(10);
                        const hashPassword = await bcrypt.hash(password,salt);
                        const doc = new UserModel({
                            name,
                            email,
                            password:hashPassword,
                            tc,
                        })
                        await doc.save();
                        const saved_user = await UserModel.findOne({email:email});
                        //Generate jwt token
                        const token = jwt.sign({ userID: saved_user._id},process.env.JWT_SECRET_KEY, {expiresIn:'5d'})
                        res.status(201).send({"status":"success","message":"Registration Successful","token":token})
                    }catch(err){
                        res.send({"status":"failed","message":"Unable to Register"});
                    }
                }else{
                    res.send({"status":"failed", "message":"password and confirm password does not match"}); 
                }

            }else{
                res.send({"status":"failed", "message":"All fields are required"});
            }
        }
    }

    static userLogin = async (req,res) => {
        try{
            const { email, password } = req.body;
            if(email && password){
                const user = await UserModel.findOne({email:email});
                if(user){
                    const isMatch = await bcrypt.compare(password,user.password);
                    if((user.email === email) && isMatch){
                        //generate jwt token
                        const token = jwt.sign({ userID: user._id},process.env.JWT_SECRET_KEY, {expiresIn:'5d'})
                        res.send({"status":"Success","message":"You are Logged In","token":token}); 
                    }else{
                        res.send({"status":"Failed","message":"Invalid Credentials"});  
                    }
                }else{
                    res.send({"status":"Failed","message":"You are not registered User"}); 
                }
            }else{
                res.send({"status":"Failed","message":"All Fields are required"});
            }
        }catch(err){
            console.log(err);
        }
    }

    static changeUserPassword = async (req,res) => {
        const { password, password_confirmation } = req.body;
        if(password && password_confirmation){
            if(password !== password_confirmation){
                res.send({"status":"Failed","message":"Password and confirm passowrd does not match"});
            }else{
               const salt = await bcrypt.genSalt(10);
               const newHashPassword = await bcrypt.hash(password, salt); 
               await UserModel.findByIdAndUpdate(req.user._id, {$set:{password:newHashPassword}})
               res.send({"status":"success","message":"changed password successfully"});
            }
        }else{
            res.send({"status":"Failed","message":"All Fields are required"});
        }
    }

    static loggedUser = async (req,res) => {
        res.send({"user": req.user});
    }

    static SendResetPasswordEmail = async (req,res) => {
        const { email } = req.body;
        if(email){
            const user = await UserModel.findOne({email:email});
            
            if(user){
                const secret = user._id + process.env.JWT_SECRET_KEY
                const token = jwt.sign({userID:user._id},secret,{expiresIn:'15m'});
                const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`;
                console.log(link);
                //send mail
                let info = await transporter.sendMail({
                    from: process.env.EMAIL_FROM, // sender address
                    to: user.email, // list of receivers
                    subject: "learning jwt to reset password", // Subject line
                    text: "reset your password", // plain text body
                    html: `<a href=${link}>Click here</a> to RESET PASSWORD`, // html body
                  });
                res.send({"status":"success","message":"Password reset email sent .. Please check you email","info":info})
            }else{
                res.send({"status":"failed","message":"email does not exist"})
            }
        }else{
            res.send({"status":"failed","message":"email field is required"})
        }
    }

    static userPasswordReset = async (req,res) => {
        const { password , password_confirmation } = req.body;
        const { id, token } = req.params;
        const user = await UserModel.findById(id);
        const new_secret = user._id + process.env.JWT_SECRET_KEY ;
        try{
            jwt.verify(token, new_secret);
            if(password && password_confirmation){
                if(password !== password_confirmation){
                    res.send({"status":"failed","message":"password and confirm password does not match"})
                }else{
                    const salt = await bcrypt.genSalt(10);
                    const newHashPassword = await bcrypt.hash(password,salt);
                    await UserModel.findOneAndUpdate(user._id, {$set:{password:newHashPassword}});
                    res.send({"status":"Success","message":"Password reset successful"})
                }
            }else{
                res.send({"status":"failed","message":"all fields are required"})
            }
        }catch(err){
            console.log(err);
            res.send({"status":"failed","message":"Invalid token"})
        }
    }
}

export default UserController;
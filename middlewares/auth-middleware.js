import jwt from 'jsonwebtoken';
import UserModel from '../models/User.js';

const checkUserAuth = async (req,res,next) => {
    let token;
    const { authorization } = req.headers;
    if(authorization && authorization.startsWith('Bearer')){
        try{
            //get token from header
            token = authorization.split(' ')[1];
            
            //verify token
            const { userID } = jwt.verify(token, process.env.JWT_SECRET_KEY);
            
            //get user from token
            req.user = await UserModel.findById(userID).select('-password');
            next();
        }catch(err){
            console.log(err);
            res.status(401).send({"status":"failed","message":"Unauthorized User"});
        }
    }
    if(!token){
        res.status(401).send({"status":"failed","message":"Unauthorized User, No Token"});
    }
}

export default checkUserAuth;
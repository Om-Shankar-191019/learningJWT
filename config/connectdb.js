import mongoose from "mongoose";

const connectDB = async (DATABASE_URL) => {
    try{
        const DB_OPTIONS = {
            dbName: "learningJWT"
        }
        await mongoose.connect(DATABASE_URL,DB_OPTIONS);
        console.log('connected db successfully!!');
    }catch(err){
        console.log(err);
    }
}

export default connectDB;